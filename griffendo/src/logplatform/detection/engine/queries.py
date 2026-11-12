"""Read side of the detection service: the one place counts, lists and summaries come from.

The Detections page, the Overview's three detection columns, the Endpoint page and the
timeline all call these functions, so their numbers agree.  "Active" means
decision = alert with at least one contributing rule enabled at its current revision
(det_detections.active = 1); suppressed and inactive (rule off / changed / deleted)
detections are only counted where a metric says so.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from ... import db
from ...settings import iso, parse_time, utc_now
from . import risk

from .registry import _correlation_summary  # noqa: E402  (avoid import cycle at module load)

_CACHE: dict[str, tuple[float, Any]] = {}
_LOCK = threading.Lock()
TTL = 120.0      # results are keyed on the detection data version, so this only bounds clock drift of 'last 7 days'
SORTS = {"time_desc": "det_time DESC, id DESC", "time_asc": "det_time ASC, id ASC",
         "score_desc": "score DESC, det_time DESC, id DESC", "severity": "severity_rank ASC, det_time DESC, id DESC",
         "occurrences": "occurrence_count DESC, det_time DESC, id DESC",
         "last_seen": "last_time DESC, id DESC"}
DETECTION_COLUMNS = ("id, entity_key, hostname, det_time, last_time, title, primary_rule_id, rule_ids, signal_rules, event_ids, "
                     "channels, category, mitre, score, severity, severity_rank, confidence, active, decision, "
                     "signal_count, event_count, user_name, process_name, summary, explanation, sources, status, "
                     "verdict, status_updated_at, suppression_id, created_at, updated_at, correlation_key, "
                     "episode_bucket, base_score, escalation_json, occurrence_count, source_mix, stage_json")


def invalidate() -> None:
    with _LOCK:
        _CACHE.clear()


def _version() -> str:
    with db.read() as connection:
        row = connection.execute("SELECT MAX(rowid), MAX(updated_at) FROM det_detections").fetchone()
    from .service import service
    return f"{row[0]}|{row[1]}|{service().registry.version}"


FRESH = 5.0   # a cached result younger than this is served without checking the data version


def _cached(key: str, producer, ttl: float = TTL):
    """Cache keyed on the detection data version.  While the engine works through a backlog the
    version changes with every batch, so every page would recompute every count; a result younger
    than FRESH seconds is therefore served as is (pages refresh every 3-60 s anyway).  Rule switches,
    verdicts and suppressions call invalidate(), so analyst actions show at once."""
    now = time.monotonic()
    with _LOCK:
        recent = _CACHE.get(f"{key}|recent")
        if recent and now - recent[0] < FRESH:
            return recent[1]
    full = f"{key}|{_version()}"
    with _LOCK:
        hit = _CACHE.get(full)
        if hit and now - hit[0] < ttl:
            _CACHE[f"{key}|recent"] = (now, hit[1])
            return hit[1]
    value = producer()
    with _LOCK:
        if len(_CACHE) > 200:
            _CACHE.clear()
        _CACHE[full] = (now, value)
        _CACHE[f"{key}|recent"] = (now, value)
    return value


def default_range(now: datetime | None = None, days: int = 7) -> tuple[str, str]:
    end = now or utc_now()
    return iso(end - timedelta(days=days)), iso(end + timedelta(minutes=5))


def _row(row, registry) -> dict[str, Any]:
    item = dict(row)
    for key in ("rule_ids", "signal_rules", "channels", "mitre", "sources"):
        item[key] = json.loads(item[key] or "[]")
    item["event_ids"] = [int(x) for x in (item["event_ids"] or "").strip(",").split(",") if x.isdigit()]
    explanation = json.loads(item.pop("explanation") or "{}")
    item["explanation"] = explanation.get("text")
    item["contributors"] = explanation.get("contributors", [])
    primary = registry.get(item["primary_rule_id"])
    item["rule_name"] = primary.name if primary else (registry.retired.get(item["primary_rule_id"]) or {}).get("name")
    item["rule_enabled"] = bool(primary and primary.enabled)
    item["rule_state"] = ("enabled" if primary and primary.enabled else "disabled" if primary
                          else "deleted" if item["primary_rule_id"] in registry.retired else "unknown")
    item["active"] = bool(item["active"])
    # v6 correlation fields (a v5 row was backfilled with its own values, so these are never null).
    escalation = json.loads(item.pop("escalation_json", None) or "{}")
    item["base_score"] = item["base_score"] if item["base_score"] is not None else item["score"]
    item["escalation"] = escalation if isinstance(escalation, dict) else {}
    item["escalated"] = bool(item["escalation"].get("applied"))
    item["occurrence_count"] = int(item.get("occurrence_count") or 0)
    item["source_mix"] = json.loads(item.pop("source_mix", None) or "[]")
    stages = json.loads(item.pop("stage_json", None) or "{}")
    item["stages"] = stages if isinstance(stages, dict) else {}
    item["stage"] = max((int(v.get("stage") or 0) for v in item["stages"].values()), default=0)
    item["staged"] = bool(item["stage"])
    item["scope"] = _scope_label(item.get("correlation_key"))
    return item


def _scope_label(correlation_key: Any) -> str:
    """Human-readable scope of an episode, derived from its correlation key."""
    if not correlation_key:
        return "unknown"
    parts = str(correlation_key).split("|")
    if len(parts) >= 4 and parts[1] == "auth":
        return f"account {parts[2]} from {parts[3] if parts[3] != 'local' else 'this host'}"
    if len(parts) >= 3 and parts[1] == "proc":
        return "process tree"
    return "all activity of this actor"


def _where(params: dict[str, Any], registry) -> tuple[str, list[Any]]:
    clauses, values = [], []
    scope = params.get("scope") or "active"
    if scope == "active":
        clauses.append("active = 1")
    elif scope == "suppressed":
        clauses.append("decision = 'suppressed'")
    elif scope == "inactive":
        clauses.append("active = 0 AND decision != 'suppressed'")
    start, end = params.get("start"), params.get("end")
    if start:
        clauses.append("det_time >= ?")
        values.append(start)
    if end:
        clauses.append("det_time <= ?")
        values.append(end)
    severities = [s for s in (params.get("severity") or []) if s in risk.RANK]
    if severities:
        clauses.append(f"severity_rank IN ({','.join('?' for _ in severities)})")
        values += [risk.RANK[s] for s in severities]
    if params.get("category"):
        clauses.append("category = ?")
        values.append(params["category"])
    if params.get("rule_id"):
        # signal_rules lists every rule that ever contributed (also switched-off, edited or deleted ones),
        # so a rule's history stays findable when its detection is still active through other rules.
        clauses.append("(primary_rule_id = ? OR signal_rules LIKE ?)")
        values += [params["rule_id"], f'%"{params["rule_id"]}"%']
    if params.get("rule"):
        clauses.append("title LIKE ?")
        values.append(f"%{params['rule']}%")
    if params.get("event_id"):
        clauses.append("event_ids LIKE ?")
        values.append(f"%,{int(params['event_id'])},%")
    if params.get("status"):
        clauses.append("status = ?")
        values.append(params["status"])
    if params.get("verdict"):
        if params["verdict"] == "none":
            clauses.append("verdict IS NULL")
        else:
            clauses.append("verdict = ?")
            values.append(params["verdict"])
    if params.get("host"):
        clauses.append("hostname = ?")
        values.append(params["host"])
    if params.get("source"):
        clauses.append("sources LIKE ?")
        values.append(f'%"{params["source"]}"%')
    if params.get("q"):
        clauses.append("(title LIKE ? OR summary LIKE ? OR user_name LIKE ? OR process_name LIKE ?)")
        values += [f"%{params['q']}%"] * 4
    if params.get("rule_state") in ("enabled", "disabled"):
        ids = [rule.id for rule in registry.rules.values() if rule.enabled]
        if params["rule_state"] == "enabled":
            clauses.append(f"primary_rule_id IN (SELECT value FROM json_each(?))")
        else:
            clauses.append(f"primary_rule_id NOT IN (SELECT value FROM json_each(?))")
        values.append(json.dumps(ids))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", values


def list_detections(params: dict[str, Any], limit: int = 50, offset: int = 0) -> dict[str, Any]:
    from .service import service
    registry = service().registry
    where, values = _where(params, registry)
    order = SORTS.get(params.get("sort") or "time_desc", SORTS["time_desc"])
    with db.read() as connection:
        rows = connection.execute(f"SELECT {DETECTION_COLUMNS} FROM det_detections{where} ORDER BY {order} "
                                  "LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        total = connection.execute(f"SELECT COUNT(*) FROM det_detections{where}", values).fetchone()[0]
    return {"items": [_row(row, registry) for row in rows], "total": total, "limit": limit, "offset": offset}


def severity_counts(start: str, end: str, scope: str = "active") -> dict[str, int]:
    def produce():
        clause = "active = 1" if scope == "active" else "decision = 'suppressed'"
        with db.read() as connection:
            rows = connection.execute(
                f"SELECT severity_rank, COUNT(*) FROM det_detections WHERE {clause} AND det_time >= ? AND det_time <= ? "
                "GROUP BY severity_rank", (start, end)).fetchall()
        counts = {name: 0 for name in risk.SEVERITIES}
        for rank, count in rows:
            counts[risk.SEVERITIES[rank]] = count
        return counts
    return _cached(f"sev|{scope}|{start[:16]}|{end[:16]}", produce)


def summary(start: str | None = None, end: str | None = None, recent: int = 5) -> dict[str, Any]:
    from .service import service
    svc = service()
    default_start, default_end = default_range()
    start, end = start or default_start, end or default_end

    def produce():
        registry = svc.registry
        counts = severity_counts(start, end)
        suppressed = sum(severity_counts(start, end, scope="suppressed").values())
        columns = {"critical_high": ["Critical", "High"], "medium": ["Medium"], "low_info": ["Low", "Informational"]}
        recent_lists = {}
        with db.read() as connection:
            for key, names in columns.items():
                ranks = [risk.RANK[n] for n in names]
                rows = connection.execute(
                    f"SELECT {DETECTION_COLUMNS} FROM det_detections WHERE active = 1 AND det_time >= ? AND det_time <= ? "
                    f"AND severity_rank IN ({','.join('?' for _ in ranks)}) ORDER BY det_time DESC, id DESC LIMIT ?",
                    (start, end, *ranks, recent)).fetchall()
                recent_lists[key] = [_row(row, registry) for row in rows]
            latest = connection.execute("SELECT MAX(det_time) FROM det_detections WHERE active = 1").fetchone()[0]
            top_rules = connection.execute(
                "SELECT primary_rule_id, title, COUNT(*) AS n, MAX(det_time) AS last FROM det_detections "
                "WHERE active = 1 AND det_time >= ? AND det_time <= ? GROUP BY primary_rule_id ORDER BY n DESC LIMIT 8",
                (start, end)).fetchall()
        rules = list(registry.rules.values())
        alerting = [r for r in rules if r.alerting]
        status = "clear"
        if counts["Critical"] or counts["High"]:
            status = "attention"
        elif counts["Medium"]:
            status = "review"
        return {
            "range": {"start": start, "end": end},
            "counts": counts, "total_active": sum(counts.values()), "suppressed": suppressed,
            "columns": {key: {"severities": names, "counts": {n: counts[n] for n in names},
                              "total": sum(counts[n] for n in names), "recent": recent_lists[key]}
                        for key, names in columns.items()},
            "latest_detection": latest, "overall_status": status,
            "top_rules": [{"rule_id": r[0], "title": r[1], "count": r[2], "last": r[3]} for r in top_rules],
            "rules": {"total": len(rules), "alerting": len(alerting),
                      "enabled": sum(1 for r in alerting if r.enabled),
                      "disabled": sum(1 for r in alerting if not r.enabled),
                      "by_origin": _count_by(rules, "origin")},
            "generated_at": iso(utc_now()),
        }
    result = dict(_cached(f"summary|{start[:16]}|{end[:16]}|{recent}", produce))
    result["model"] = svc.behavior.status()
    result["processing"] = processing_status()
    return result


def _count_by(rules, attribute: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rule in rules:
        key = getattr(rule, attribute)
        counts[key] = counts.get(key, 0) + 1
    return counts


def processing_status() -> dict[str, Any]:
    from .service import service
    svc = service()
    return {"backlog_events": svc.backlog(), "replaying": svc.replaying,
            **{k: v for k, v in svc.stats.items() if k != "last_error"},
            "last_error": (svc.stats.get("last_error") or "")[:300] or None, "jobs": svc.running_jobs(),
            "state": svc.state.stats(), "rule_load_errors": svc.registry.errors[:20]}


def get_detection(detection_id: str) -> dict[str, Any] | None:
    from .service import service
    svc = service()
    registry = svc.registry
    with db.read() as connection:
        row = connection.execute(f"SELECT {DETECTION_COLUMNS} FROM det_detections WHERE id = ?",
                                 (detection_id,)).fetchone()
        if not row:
            return None
        signals = connection.execute(
            "SELECT id, rule_id, rule_rev, rule_name, source, kind, first_time, last_time, score, severity, confidence, "
            "decision, suppression_id, event_keys, evidence_json, details_json, origin, created_at FROM det_signals "
            "WHERE detection_id = ? ORDER BY first_time, id", (detection_id,)).fetchall()
        keys = []
        for signal in signals:
            keys += json.loads(signal["event_keys"])
        keys = list(dict.fromkeys(k for k in keys if not k.startswith("rate:")))
        stored = {}
        for start in range(0, len(keys), 400):
            chunk = keys[start:start + 400]
            for event in connection.execute(
                    "SELECT id, event_time, channel, provider, event_id, record_id, hostname, normalized_json "
                    f"FROM events WHERE id IN ({','.join('?' for _ in chunk)})", chunk):
                stored[event["id"]] = event
    detection = _row(row, registry)
    signal_items, timeline, rules = [], [], {}
    for signal in signals:
        rule = registry.get(signal["rule_id"])
        current = bool(rule and rule.rev == signal["rule_rev"])
        details = json.loads(signal["details_json"])
        evidence = json.loads(signal["evidence_json"])
        signal_items.append({
            "id": signal["id"], "rule_id": signal["rule_id"], "rule_name": signal["rule_name"],
            "source": signal["source"], "kind": signal["kind"], "first_time": signal["first_time"],
            "last_time": signal["last_time"], "score": signal["score"], "severity": signal["severity"],
            "confidence": signal["confidence"], "decision": signal["decision"],
            "suppression_id": signal["suppression_id"], "origin": signal["origin"],
            "rule_state": ("enabled" if rule and rule.enabled and current else
                           "changed since detection" if rule and not current else
                           "disabled" if rule else "deleted"),
            "details": details, "evidence": evidence, "event_keys": json.loads(signal["event_keys"]),
        })
        for item in evidence:
            timeline.append({"time": item.get("@timestamp"), "event_key": item.get("event_key"),
                             "event_id": item.get("event.code"), "channel": item.get("winlog.channel"),
                             "rule_id": signal["rule_id"], "summary": _evidence_line(item),
                             "available": item.get("event_key") in stored})
        if rule and rule.id not in rules:
            public = rule.public()
            # `correlation` is computed by Rule.public() but was missing from this whitelist, so the
            # detection detail view showed no correlation block (including the DSIEM stages) even
            # though the episode itself was staged. Keep it, and fall back to the rule spec.
            public["correlation"] = public.get("correlation") or _correlation_summary(rule.spec)
            rules[rule.id] = {key: public[key] for key in ("rule_id", "name", "kind", "origin", "origin_label",
                                                           "severity", "score", "confidence", "category", "description",
                                                           "enabled", "rev", "sources", "mitre", "support", "source",
                                                           "modifications", "investigation", "false_positives",
                                                           "correlation", "verified")}
            rules[rule.id]["condition"] = rule.spec.get("condition") or rule.spec.get("steps") or \
                (rule.spec.get("chain") or {}).get("steps") or (rule.spec.get("wazuh") or {}).get("condition")
            rules[rule.id]["source"] = {k: v for k, v in rules[rule.id]["source"].items() if k != "original_query"}
            rules[rule.id]["original_query"] = (rule.spec.get("source") or {}).get("original_query")
        elif not rule and signal["rule_id"] in registry.retired:
            rules[signal["rule_id"]] = {**registry.retired[signal["rule_id"]], "deleted": True}
    timeline.sort(key=lambda item: (item["time"] or "", item["event_key"] or ""))
    seen = set()
    unique_timeline = []
    for item in timeline:
        marker = (item["event_key"], item["rule_id"])
        if marker in seen:
            continue
        seen.add(marker)
        unique_timeline.append(item)
    events = {}
    for key, event in stored.items():
        normalized = json.loads(event["normalized_json"])
        events[key] = {"event_key": key, "time": event["event_time"], "channel": event["channel"],
                       "provider": event["provider"], "event_id": event["event_id"], "record_id": event["record_id"],
                       "hostname": event["hostname"], "fields": normalized.get("fields") or {}}
    steps = []
    for rule_id in rules:
        investigation = rules[rule_id].get("investigation")
        if investigation:
            steps.append({"rule_id": rule_id, "text": investigation})
    detection.update(signals=signal_items, timeline=unique_timeline, events=events, rules=rules,
                     investigation=steps, status_history=svc.state_store.history(detection_id),
                     verdicts=svc.state_store.verdicts(detection_id),
                     explanation_detail=json.loads(row["explanation"] or "{}"),
                     severity_bands=dict(zip(("critical", "high", "medium", "low"), risk.thresholds())))
    return detection


def _evidence_line(item: dict[str, Any]) -> str:
    parts = []
    for key in ("process.name", "process.command_line", "user.name", "service.name", "scheduled_task.name",
                "registry.path", "file.path", "source.ip", "destination.ip", "dns.question.name"):
        if item.get(key):
            value = str(item[key])
            parts.append(f"{key}={value[:120]}")
    if item.get("griffendo.rate"):
        rate = item["griffendo.rate"]
        parts.append(f"{rate['feature']}={rate['value']:.0f} (mean {rate['mean']}, sd {rate['sd']})")
    return " · ".join(parts[:4])


def timeline_page(params: dict[str, Any], limit: int = 200) -> dict[str, Any]:
    """Active detections of the window, oldest first, keyset-paged on (det_time, id)."""
    from .service import service
    registry = service().registry
    where, values = _where({**params, "scope": "active"}, registry)
    after, before = params.get("after"), params.get("before")
    position = params.get("position")
    order = "det_time ASC, id ASC"
    extra, extra_values = [], []
    if after:
        t, i = _decode(after)
        extra.append("(det_time > ? OR (det_time = ? AND id > ?))")
        extra_values += [t, t, i]
    if before or position == "end":
        order = "det_time DESC, id DESC"
        if before:
            t, i = _decode(before)
            extra.append("(det_time < ? OR (det_time = ? AND id < ?))")
            extra_values += [t, t, i]
    clause = where + ((" AND " if where else " WHERE ") + " AND ".join(extra) if extra else "")
    with db.read() as connection:
        rows = connection.execute(f"SELECT {DETECTION_COLUMNS} FROM det_detections{clause} ORDER BY {order} LIMIT ?",
                                  (*values, *extra_values, limit + 1)).fetchall()
        total = connection.execute(f"SELECT COUNT(*) FROM det_detections{where}", values).fetchone()[0]
    more = len(rows) > limit
    rows = rows[:limit]
    if order.startswith("det_time DESC"):
        rows = list(reversed(rows))
    items = [_row(row, registry) for row in rows]
    for item in items:
        item["cursor"] = _encode(item["det_time"], item["id"])
    has_older = bool(items) and (more if order.startswith("det_time DESC") else bool(after))
    has_newer = bool(items) and (more if not order.startswith("det_time DESC") else bool(before))
    return {"items": items, "total": total, "older_cursor": items[0]["cursor"] if items else None,
            "newer_cursor": items[-1]["cursor"] if items else None, "has_older": has_older, "has_newer": has_newer}


def _encode(t: str, i: str) -> str:
    return base64.urlsafe_b64encode(f"{t}|{i}".encode()).decode().rstrip("=")


def _decode(cursor: str) -> tuple[str, str]:
    padded = cursor + "=" * (-len(cursor) % 4)
    t, i = base64.urlsafe_b64decode(padded.encode()).decode().split("|", 1)
    if parse_time(t) is None:
        raise ValueError("bad cursor")
    return t, i


def rule_stats() -> dict[str, dict[str, Any]]:
    def produce():
        start = iso(utc_now() - timedelta(days=7))
        with db.read() as connection:
            rows = connection.execute(
                "SELECT rule_id, COUNT(*) AS signals, MIN(first_time) AS first, MAX(last_time) AS last, "
                "SUM(CASE WHEN last_time >= ? THEN 1 ELSE 0 END) AS recent, "
                "SUM(CASE WHEN decision = 'suppressed' THEN 1 ELSE 0 END) AS suppressed, "
                "SUM(CASE WHEN decision IN ('learn_only', 'shadow') THEN 1 ELSE 0 END) AS learning, "
                "SUM(CASE WHEN origin = 'reevaluation' THEN 1 ELSE 0 END) AS reevaluated "
                "FROM det_signals GROUP BY rule_id", (start,)).fetchall()
            active = connection.execute(
                "SELECT primary_rule_id, COUNT(*) FROM det_detections WHERE active = 1 AND det_time >= ? "
                "GROUP BY primary_rule_id", (start,)).fetchall()
        result = {row["rule_id"]: dict(row) for row in rows}
        for rule_id, count in active:
            result.setdefault(rule_id, {"rule_id": rule_id, "signals": 0})["active_detections_7d"] = count
        return result
    return _cached("rule-stats", produce, ttl=120)


def rules(params: dict[str, Any]) -> dict[str, Any]:
    from .service import service
    svc = service()
    stats = rule_stats()
    items = []
    q = (params.get("q") or "").lower()
    for rule in svc.registry.rules.values():
        if params.get("origin") and rule.origin != params["origin"]:
            continue
        if params.get("kind") and rule.kind != params["kind"]:
            continue
        if params.get("state") == "enabled" and not rule.enabled:
            continue
        if params.get("state") == "disabled" and rule.enabled:
            continue
        if params.get("severity") and rule.severity != params["severity"]:
            continue
        if params.get("support") and (rule.spec.get("support") or {}).get("status") != params["support"]:
            continue
        if not params.get("include_grouping") and not rule.alerting:
            continue
        if q and q not in rule.name.lower() and q not in rule.id.lower() and q not in (rule.category or "").lower() \
                and not any(q == str(i) for s in rule.sources for i in s.get("event_ids") or []):
            continue
        stat = stats.get(rule.id, {})
        items.append({
            "rule_id": rule.id, "name": rule.name, "kind": rule.kind, "origin": rule.origin,
            "severity": rule.severity, "score": rule.score, "category": rule.category, "enabled": rule.enabled,
            "protected": rule.protected, "support": (rule.spec.get("support") or {}).get("status"),
            "optional_sources": (rule.spec.get("support") or {}).get("optional_sources") or [],
            "channels": sorted({s["channel"] for s in rule.sources}),
            "event_ids": sorted({i for s in rule.sources for i in s.get("event_ids") or []})[:12],
            "signals": stat.get("signals", 0), "signals_7d": stat.get("recent", 0),
            "active_detections_7d": stat.get("active_detections_7d", 0), "first_signal": stat.get("first"),
            "last_signal": stat.get("last"), "suppressed": stat.get("suppressed", 0),
            "reevaluated": stat.get("reevaluated", 0),
            "mitre": sorted({m.get("technique") for m in rule.spec.get("mitre") or [] if m.get("technique")})[:4],
            "job": svc.job(rule.id), "modified_at": rule.spec.get("modified_at"),
        })
    sort = params.get("sort") or "signals"
    keyfuncs = {"signals": lambda r: (-r["signals"], r["name"]), "name": lambda r: r["name"].lower(),
                "severity": lambda r: (risk.RANK[r["severity"]], r["name"]),
                "recent": lambda r: (r["last_signal"] is None, "" if r["last_signal"] is None else
                                     "".join(chr(0x10FFFF - ord(c)) for c in r["last_signal"]))}
    items.sort(key=keyfuncs.get(sort, keyfuncs["signals"]))
    limit = min(int(params.get("limit") or 200), 2000)
    offset = int(params.get("offset") or 0)
    return {"items": items[offset:offset + limit], "total": len(items),
            "counts": {"enabled": sum(1 for r in items if r["enabled"]), "disabled": sum(1 for r in items if not r["enabled"]),
                       "triggered": sum(1 for r in items if r["signals"]), "never": sum(1 for r in items if not r["signals"])},
            "suppressions": svc.state_store.suppressions(include_revoked=True)[:200],
            "load_errors": svc.registry.errors[:20]}


def rule_detail(rule_id: str) -> dict[str, Any] | None:
    from .service import service
    svc = service()
    rule = svc.registry.get(rule_id)
    if rule is None:
        retired = svc.registry.retired.get(rule_id)
        return {**retired, "deleted": True} if retired else None
    public = rule.public()
    public["condition"] = rule.spec.get("condition")
    public["steps"] = rule.spec.get("steps")
    public["chain"] = rule.spec.get("chain")
    public["wazuh"] = rule.spec.get("wazuh")
    public["threshold"] = rule.spec.get("threshold")
    public["new_terms"] = rule.spec.get("new_terms")
    public["maxspan"] = rule.spec.get("maxspan")
    public["explanation"] = rule.spec.get("explanation")
    public["original_query"] = (rule.spec.get("source") or {}).get("original_query")
    public["stats"] = rule_stats().get(rule_id, {})
    public["job"] = svc.job(rule_id)
    public["changes"] = svc.state_store.rule_changes(rule_id)
    return public
