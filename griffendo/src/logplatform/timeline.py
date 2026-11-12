"""Seven-day timeline queries with keyset (cursor) pagination.

Pages are ordered by (event_time, id) and continued with an opaque cursor that
encodes the last row's sort key, so events arriving while a user pages never
shift, skip or repeat rows (unlike LIMIT/OFFSET).  'newer_than' returns rows
above the first row the browser already shows, for live updates.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from typing import Any

from . import anomalies, db
from .settings import iso, parse_time, utc_now

LEVELS = ("Critical", "Error", "Warning", "Informational", "Verbose")
_COUNT_CACHE: dict[str, tuple[int, int]] = {}


def encode_cursor(event_time: str, event_key: str) -> str:
    return base64.urlsafe_b64encode(json.dumps([event_time, event_key]).encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[str, str]:
    padded = cursor + "=" * (-len(cursor) % 4)
    value = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    if not (isinstance(value, list) and len(value) == 2 and all(isinstance(part, str) for part in value)):
        raise ValueError("bad cursor")
    return value[0], value[1]


def _where(params: dict[str, Any], now: datetime) -> tuple[str, list[Any], dict[str, str]]:
    days = anomalies.load_catalog()["window_days"]
    start, end = now - timedelta(days=days), now + anomalies.FUTURE_TOLERANCE
    since = parse_time(params.get("since")) if params.get("since") else None
    until = parse_time(params.get("until")) if params.get("until") else None
    # The timeline is the analysis window; narrower ranges are allowed inside it.
    lower = max(start, since) if since else start
    upper = min(end, until) if until else end
    clauses = ["e.event_time >= ?", "e.event_time <= ?"]
    values: list[Any] = [iso(lower), iso(upper)]
    for key, column in (("channel", "e.channel"), ("provider", "e.provider"), ("host", "e.hostname"),
                        ("event_id", "e.event_id")):
        if params.get(key) not in (None, ""):
            clauses.append(f"{column} = ?")
            values.append(params[key])
    levels = [item for item in (params.get("level") or "").split(",") if item in LEVELS]
    if levels:
        clauses.append(f"e.severity IN ({','.join('?' for _ in levels)})")
        values.extend(levels)
    anomaly_severities = [item for item in (params.get("anomaly_severity") or "").split(",") if item]
    if params.get("anomalies_only") or anomaly_severities:
        # v5: "flagged" = the event is evidence of an active detection.
        sub = ("SELECT 1 FROM det_event_index x JOIN det_detections d ON d.id = x.detection_id AND d.active = 1 "
               "WHERE x.event_key = e.id")
        if anomaly_severities:
            sub += f" AND d.severity IN ({','.join('?' for _ in anomaly_severities)})"
            values.extend(anomaly_severities)
        clauses.append(f"EXISTS ({sub})")
    if params.get("q"):
        clauses.append("(e.provider LIKE ? OR e.username LIKE ? OR e.process_name LIKE ? OR e.command_line LIKE ? "
                       "OR e.hostname LIKE ? OR CAST(e.event_id AS TEXT) = ?)")
        text = str(params["q"]).strip()
        values.extend([f"%{text}%"] * 5 + [text])
    return " AND ".join(clauses), values, {"start": iso(lower), "end": iso(upper), "window_start": iso(start)}


def page(params: dict[str, Any], limit: int = 200, now: datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    order = "asc" if params.get("order") == "asc" else "desc"
    where, values, bounds = _where(params, now)
    keyset, key_values = "", []
    cursor = params.get("cursor")
    newer = params.get("newer_than")
    if cursor:
        time_key, id_key = decode_cursor(cursor)
        keyset = " AND (e.event_time, e.id) < (?, ?)" if order == "desc" else " AND (e.event_time, e.id) > (?, ?)"
        key_values = [time_key, id_key]
    elif newer:
        time_key, id_key = decode_cursor(newer)
        keyset = " AND (e.event_time, e.id) > (?, ?)"
        key_values = [time_key, id_key]
    direction = "DESC" if order == "desc" else "ASC"
    if newer:
        direction = "ASC"   # oldest-first above the top row, so a capped batch never leaves a hole
    sql = (f"SELECT e.id, e.event_time, e.timestamp, e.received_at, e.hostname, e.channel, e.provider, e.event_id, "
           f"e.severity, e.username, e.process_name, e.record_id FROM events e WHERE {where}{keyset} "
           f"ORDER BY e.event_time {direction}, e.id {direction} LIMIT ?")
    with db.read() as connection:
        rows = connection.execute(sql, [*values, *key_values, limit + 1]).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        if newer:
            rows = list(reversed(rows))
        flags: dict[str, dict[str, Any]] = {}
        if rows:
            keys = [row["id"] for row in rows]
            for flag in connection.execute(
                    f"SELECT x.event_key AS event_key, MIN(d.severity_rank) AS rank, COUNT(*) AS rules, "
                    f"GROUP_CONCAT(d.title, ' | ') AS names, MIN(d.severity) AS severity FROM det_event_index x "
                    f"JOIN det_detections d ON d.id = x.detection_id AND d.active = 1 "
                    f"WHERE x.event_key IN ({','.join('?' for _ in keys)}) GROUP BY x.event_key", keys):
                flags[flag["event_key"]] = dict(flag)
        count_key = json.dumps([where, values])
        max_rowid = connection.execute("SELECT MAX(rowid) FROM events").fetchone()[0] or 0
        cached = _COUNT_CACHE.get(count_key)
        if cached and cached[0] == max_rowid:
            total = cached[1]
        else:
            total = connection.execute(f"SELECT COUNT(*) FROM events e WHERE {where}", values).fetchone()[0]
            if len(_COUNT_CACHE) > 64:
                _COUNT_CACHE.clear()
            _COUNT_CACHE[count_key] = (max_rowid, total)
    from .detection.engine.risk import SEVERITIES as severity_order
    items = []
    for row in rows:
        item = dict(row)
        item["label"] = anomalies.rule_name(row["channel"], row["event_id"]) or row["provider"] or "Windows event"
        flag = flags.get(row["id"])
        if flag:
            item["anomaly"] = {"severity": severity_order[flag["rank"]] if flag["rank"] < len(severity_order) else flag["severity"],
                               "rules": flag["rules"], "names": flag["names"]}
        items.append(item)
    next_cursor = None
    if has_more and rows and not newer:
        last = rows[-1]
        next_cursor = encode_cursor(last["event_time"], last["id"])
    top_cursor = encode_cursor(rows[0]["event_time"], rows[0]["id"]) if rows else None
    first_page = not cursor and not newer
    coverage = anomalies._cached("timeline-coverage", lambda: anomalies.coverage_overview(now), ttl=5) if first_page else None
    return {
        "items": items, "next_cursor": next_cursor, "top_cursor": top_cursor, "has_more": has_more,
        "total": total, "order": order, "range": bounds, "generated_at": iso(utc_now()),
        "coverage": ({"state": coverage["state"], "label": coverage["label"], "missing": coverage["missing"],
                      "available": coverage["available"]} if coverage else None),
    }


# --------------------------------------------------------------------------- anomaly timeline (v4)
# The Timeline view lists ACTIVE anomalies (enabled rules, current definition - the same join the
# Anomalies view and counts use) from the rolling window, oldest first.  One entry per event: when
# several rules flag the same event they are listed together, never as duplicate entries.
# Sort key: (event_time, record_id or -1, event_key) - stable for equal timestamps.
SORT_KEY = "a.event_time, IFNULL(a.record_id, -1), a.event_key"


def encode_anomaly_cursor(event_time: str, record: int, event_key: str) -> str:
    return base64.urlsafe_b64encode(json.dumps([event_time, record, event_key]).encode()).decode().rstrip("=")


def decode_anomaly_cursor(cursor: str) -> tuple[str, int, str]:
    padded = cursor + "=" * (-len(cursor) % 4)
    value = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    if not (isinstance(value, list) and len(value) == 3 and isinstance(value[0], str) and isinstance(value[1], int)
            and isinstance(value[2], str)):
        raise ValueError("bad cursor")
    return value[0], value[1], value[2]


def _anomaly_where(params: dict[str, Any], now: datetime) -> tuple[str, list[Any], dict[str, str]]:
    start, end = anomalies.window(now)
    upper_limit = end + anomalies.FUTURE_TOLERANCE
    since = parse_time(params.get("since")) if params.get("since") else None
    until = parse_time(params.get("until")) if params.get("until") else None
    lower = max(start, since) if since else start
    upper = min(upper_limit, until) if until else upper_limit
    clauses = ["a.event_time >= ?", "a.event_time <= ?"]
    values: list[Any] = [iso(lower), iso(upper)]
    for key, column in (("channel", "a.channel"), ("host", "a.hostname"), ("event_id", "a.event_id"),
                        ("rule_id", "a.rule_id")):
        if params.get(key) not in (None, ""):
            clauses.append(f"{column} = ?")
            values.append(params[key])
    severities = [item for item in (params.get("severity") or "").split(",") if item]
    if severities:
        clauses.append(f"r.severity IN ({','.join('?' for _ in severities)})")
        values.extend(severities)
    if params.get("q"):
        text = str(params["q"]).strip()
        clauses.append("(r.name LIKE ? OR a.hostname LIKE ? OR a.username LIKE ? OR a.provider LIKE ? "
                       "OR a.source_address LIKE ? OR CAST(a.event_id AS TEXT) = ?)")
        values.extend([f"%{text}%"] * 5 + [text])
    return " AND ".join(clauses), values, {"start": iso(lower), "end": iso(upper), "window_start": iso(start),
                                           "window_end": iso(end)}


ENTRY_COLUMNS = ("a.id, a.event_key, a.rule_id, a.record_id, a.event_id, a.channel, a.provider, a.hostname, "
                 "a.username, a.source_address, a.event_time, a.event_time_source, a.status, a.detection_source, "
                 "a.rule_origin, a.rowid AS seq, r.name AS rule_name, r.severity AS rule_severity, "
                 "r.severity_rank AS rule_rank, r.category AS rule_category")


def _entries(rows: list[Any]) -> list[dict[str, Any]]:
    """Merge detection rows (already in sort order) into one entry per event."""
    entries: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = by_key.get(row["event_key"])
        if entry is None:
            record = row["record_id"] if row["record_id"] is not None else -1
            entry = {"key": row["event_key"], "cursor": encode_anomaly_cursor(row["event_time"], record, row["event_key"]),
                     "sort": [row["event_time"], record, row["event_key"]],
                     "event_time": row["event_time"], "event_time_source": row["event_time_source"],
                     "record_id": row["record_id"], "event_id": row["event_id"], "channel": row["channel"],
                     "provider": row["provider"], "hostname": row["hostname"], "username": row["username"],
                     "source_address": row["source_address"], "detections": [], "seq": 0}
            by_key[row["event_key"]] = entry
            entries.append(entry)
        if any(item["rule_id"] == row["rule_id"] for item in entry["detections"]):
            continue
        entry["detections"].append({"id": row["id"], "rule_id": row["rule_id"], "name": row["rule_name"],
                                    "severity": row["rule_severity"], "rank": row["rule_rank"],
                                    "category": row["rule_category"], "status": row["status"],
                                    "source": row["detection_source"], "origin": row["rule_origin"]})
        entry["seq"] = max(entry["seq"], row["seq"])
    for entry in entries:
        entry["detections"].sort(key=lambda item: (item["rank"], item["rule_id"]))
        top = entry["detections"][0]
        entry.update(name=top["name"], severity=top["severity"], rule_id=top["rule_id"], detection_id=top["id"])
    return entries


def anomaly_page(params: dict[str, Any], limit: int = 200, now: datetime | None = None) -> dict[str, Any]:
    """One page of the anomaly timeline, oldest first.

    after=<cursor>   entries after that entry (scrolling down / newer)
    before=<cursor>  entries before it (scrolling up / older); position=end gives the newest page
    changed_since=<seq>  entries with a detection recorded after that sequence number (live updates,
                     including detections restored or added for older events by a re-evaluation)
    """
    now = now or utc_now()
    where, values, bounds = _anomaly_where(params, now)
    cte, cte_values = anomalies._active_cte()
    base = f"WITH {cte} SELECT {ENTRY_COLUMNS} FROM anomalies a CROSS JOIN active_rules r"
    join_where = ("a.rule_id = r.rule_id AND a.event_id = r.event_id AND lower(a.channel) = r.channel "
                  "AND (r.provider IS NULL OR lower(IFNULL(a.provider, '')) = r.provider)")
    after, before = params.get("after"), params.get("before")
    changed_since = params.get("changed_since")
    backwards = bool(before) or params.get("position") == "end"
    keyset, key_values = "", []
    if after:
        keyset, key_values = f" AND ({SORT_KEY}) > (?, ?, ?)", list(decode_anomaly_cursor(after))
    elif before:
        keyset, key_values = f" AND ({SORT_KEY}) < (?, ?, ?)", list(decode_anomaly_cursor(before))
    order = "DESC" if backwards else "ASC"
    order_sql = f" ORDER BY a.event_time {order}, IFNULL(a.record_id, -1) {order}, a.event_key {order}"
    with db.read() as connection:
        seq = connection.execute("SELECT MAX(rowid) FROM anomalies").fetchone()[0] or 0
        if changed_since is not None:
            keys = [row[0] for row in connection.execute(
                f"WITH {cte} SELECT DISTINCT a.event_key FROM anomalies a {anomalies.ACTIVE_JOIN} "
                f"WHERE a.rowid > ? AND {where} LIMIT 2001", [*cte_values, int(changed_since), *values])]
            truncated = len(keys) > 2000
            rows = []
            for offset in range(0, min(len(keys), 2000), 500):
                chunk = keys[offset:offset + 500]
                rows += connection.execute(
                    f"{base} WHERE {join_where} AND {where} AND a.event_key IN ({','.join('?' for _ in chunk)})",
                    [*cte_values, *values, *chunk]).fetchall()
            rows.sort(key=lambda row: (row["event_time"], row["record_id"] if row["record_id"] is not None else -1,
                                       row["event_key"]))
            items = _entries(rows)
            return {"items": items, "seq": seq, "changed_since": int(changed_since), "truncated": truncated,
                    "range": bounds, "generated_at": iso(utc_now())}
        rows = connection.execute(f"{base} WHERE {join_where} AND {where}{keyset}{order_sql} LIMIT ?",
                                  [*cte_values, *values, *key_values, limit + 1]).fetchall()
        more = len(rows) > limit
        extra = rows[limit] if more else None
        rows = rows[:limit]
        if more and rows and extra["event_key"] == rows[-1]["event_key"]:
            # The page boundary fell inside one event's detections: complete that event, then check for more.
            last = rows[-1]
            rows += connection.execute(f"{base} WHERE {join_where} AND {where} AND a.event_key = ?",
                                       [*cte_values, *values, last["event_key"]]).fetchall()
            record = last["record_id"] if last["record_id"] is not None else -1
            comparison = "<" if backwards else ">"
            more = connection.execute(
                f"WITH {cte} SELECT 1 FROM anomalies a {anomalies.ACTIVE_JOIN} WHERE {where} "
                f"AND ({SORT_KEY}) {comparison} (?, ?, ?) LIMIT 1",
                [*cte_values, *values, last["event_time"], record, last["event_key"]]).fetchone() is not None
        total = (None, None)
        if not after and not before:
            # Totals only for a first/last page (the browser keeps them up to date from live changes).
            filters = {key: value for key, value in params.items() if key not in ("after", "before", "position")}
            total_key = (f"anomaly-timeline-total-{json.dumps(filters, default=str)}-{bounds['window_start'][:16]}-"
                         f"{seq}-{anomalies.rules_version()}")
            total = anomalies._cached(total_key, lambda: tuple(connection.execute(
                f"WITH {cte} SELECT COUNT(DISTINCT a.event_key), COUNT(*) FROM anomalies a {anomalies.ACTIVE_JOIN} "
                f"WHERE {where}", [*cte_values, *values]).fetchone()), ttl=60)
    if backwards:
        rows = list(reversed(rows))
    items = _entries(rows)
    first, last = (items[0], items[-1]) if items else (None, None)
    if backwards:
        has_older, has_newer = more, bool(before)
    else:
        has_newer, has_older = more, bool(after)
    if not items:
        has_newer = has_newer and False
    first_page = not after and not before
    coverage = anomalies._cached("timeline-coverage", lambda: anomalies.coverage_overview(now), ttl=5) if first_page else None
    return {
        "items": items, "seq": seq,
        "older_cursor": first["cursor"] if first else None,
        "newer_cursor": last["cursor"] if last else None,
        "has_older": has_older, "has_newer": has_newer,
        "total_events": total[0], "total_detections": total[1], "order": "oldest_first",
        "range": bounds, "generated_at": iso(utc_now()),
        "coverage": ({"state": coverage["state"], "label": coverage["label"], "missing": coverage["missing"],
                      "available": coverage["available"]} if coverage else None),
    }
