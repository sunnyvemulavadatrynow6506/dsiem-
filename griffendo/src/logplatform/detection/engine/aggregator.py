"""Signal aggregator: groups signals that belong to the same entity and time bucket into one detection.

Entity (first available, system accounts and system logon sessions excluded because they
would join unrelated activity):  logon session -> user -> Sysmon process GUID.  Signals with
no entity join the detection that already holds one of their evidence events (so several
rules matching the same event make one detection); otherwise they are grouped per rule.
Buckets are fixed GRIFFENDO_AGGREGATION_MINUTES (default 30) slices of event time, so the
grouping does not depend on the order events arrive in.  A detection's score is computed
by risk.combine() from its *active* signals (enabled rule at its current revision, decision
'alert'); it is recomputed whenever a rule is switched, edited or deleted.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from ...settings import env_int, iso, utc_now
from . import normalizer, risk
from .state import epoch


def bucket_seconds() -> int:
    return env_int("GRIFFENDO_AGGREGATION_MINUTES", 30, 1) * 60


def entity_key(ev: dict[str, Any]) -> str | None:
    ent = normalizer.entity(ev)
    for name in ("logon", "user", "process"):
        if ent.get(name):
            return f"{name}:{ent[name]}"
    return None


def detection_id(key: str, bucket: int) -> str:
    return hashlib.sha256(f"{key}|{bucket}".encode("utf-8")).hexdigest()[:32]


class Aggregator:
    def __init__(self, registry_getter):
        self.registry = registry_getter

    # ------------------------------------------------------------------ write path
    def persist(self, connection, signals: list[dict[str, Any]], trigger: dict[str, Any] | None, origin: str) \
            -> set[str]:
        """Store the signals produced by one event (or one correlation) and return touched detection ids."""
        if not signals:
            return set()
        touched: set[str] = set()
        now = iso(utc_now())
        top = max(signals, key=lambda s: (s["score"], s["rule_id"]))
        key = None
        for source in ([trigger] if trigger else []) + [ev for s in signals for ev in s["events"]]:
            key = entity_key(source)
            if key:
                break
        group_id = None
        if key is None:
            keys = [k for s in signals for k in s["event_keys"]]
            for start in range(0, len(keys), 400):
                chunk = keys[start:start + 400]
                row = connection.execute(
                    f"SELECT detection_id FROM det_event_index WHERE event_key IN ({','.join('?' for _ in chunk)}) "
                    "LIMIT 1", chunk).fetchone()
                if row:
                    group_id = row[0]
                    break
            key = f"rule:{top['rule_id']}"
        anchor = trigger["@timestamp"] if trigger and trigger.get("@timestamp") else top["first_time"]
        bucket = int(epoch(anchor) // bucket_seconds())
        if group_id is None:
            group_id = detection_id(key, bucket)
        for signal in signals:
            if signal.get("retract"):
                row = connection.execute("SELECT detection_id FROM det_signals WHERE id = ?", (signal["retract"],)).fetchone()
                connection.execute("UPDATE det_signals SET decision = 'retracted' WHERE id = ?", (signal["retract"],))
                if row and row[0]:
                    touched.add(row[0])
            evidence = [normalizer.summary(ev) for ev in signal["events"]]
            cursor = connection.execute(
                """INSERT OR IGNORE INTO det_signals(id, rule_id, rule_rev, rule_name, source, kind, first_time, last_time,
                       detection_id, entity_key, score, severity, confidence, decision, suppression_id, event_keys,
                       evidence_json, details_json, origin, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (signal["id"], signal["rule_id"], signal["rule_rev"], signal["rule"].name, signal["source"],
                 signal["kind"], signal["first_time"], signal["last_time"], group_id, key, signal["score"],
                 signal["severity"], signal["confidence"], signal["decision"], signal.get("suppression_id"),
                 json.dumps(signal["event_keys"]), json.dumps(evidence, default=str),
                 json.dumps(signal["details"], default=str), origin, now))
            if not cursor.rowcount:
                continue
            if signal["decision"] in ("learn_only", "shadow"):
                continue
            touched.add(group_id)
            connection.executemany("INSERT OR IGNORE INTO det_event_index(event_key, detection_id) VALUES (?, ?)",
                                   [(k, group_id) for k in signal["event_keys"]])
        if touched and group_id in touched:
            connection.execute(
                """INSERT OR IGNORE INTO det_detections(id, entity_key, bucket, hostname, det_time, last_time, title,
                       primary_rule_id, rule_ids, event_ids, channels, category, mitre, score, severity, severity_rank,
                       confidence, active, decision, signal_count, event_count, sources, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '', '[]', NULL, '[]', 0, 'Informational', 4, 'low', 0,
                           'pending', 0, 0, '[]', ?, ?)""",
                (group_id, key, bucket, (signals[0]["events"][0] or {}).get("host.name"), top["first_time"],
                 top["last_time"], top["rule"].name, top["rule_id"], now, now))
        return touched

    # ------------------------------------------------------------------ recompute
    def recompute(self, connection, ids: Iterable[str]) -> int:
        registry = self.registry()
        changed = 0
        now = iso(utc_now())
        ids = list(ids)
        for start in range(0, len(ids), 300):
            chunk = ids[start:start + 300]
            rows = connection.execute(
                f"SELECT id, detection_id, rule_id, rule_rev, rule_name, source, first_time, last_time, score, "
                f"severity, confidence, decision, suppression_id, event_keys, evidence_json FROM det_signals "
                f"WHERE detection_id IN ({','.join('?' for _ in chunk)})", chunk).fetchall()
            grouped: dict[str, list[dict[str, Any]]] = {i: [] for i in chunk}
            for row in rows:
                item = dict(row)
                item["event_keys"] = json.loads(item["event_keys"])
                grouped[row["detection_id"]].append(item)
            for det_id, signals in grouped.items():
                self._update(connection, det_id, signals, registry, now)
                changed += 1
        return changed

    def _update(self, connection, det_id: str, signals: list[dict[str, Any]], registry, now: str) -> None:
        def is_active(signal: dict[str, Any]) -> bool:
            rule = registry.get(signal["rule_id"])
            return bool(rule and rule.enabled and rule.rev == signal["rule_rev"])
        alerting = [s for s in signals if s["decision"] == "alert" and is_active(s)]
        suppressed = [s for s in signals if s["decision"] == "suppressed" and is_active(s)]
        basis = alerting or suppressed or [s for s in signals if s["decision"] not in ("learn_only", "shadow")] \
            or signals
        if not basis:
            return
        combined = risk.combine(basis)
        top = max(basis, key=lambda s: (s["score"], s["rule_id"]))
        rule_ids = sorted({s["rule_id"] for s in basis}, key=lambda r: (r != top["rule_id"], r))
        evidence: list[dict[str, Any]] = []
        for signal in basis:
            evidence += json.loads(signal["evidence_json"])
        event_ids = sorted({str(item.get("event.code")) for item in evidence if item.get("event.code")},
                           key=lambda c: int(c) if c.isdigit() else 0)
        channels = sorted({item.get("winlog.channel") for item in evidence if item.get("winlog.channel")})
        users = [item.get("user.name") for item in evidence if item.get("user.name")]
        processes = [item.get("process.name") for item in evidence if item.get("process.name")]
        mitre, category = [], None
        rules = {}
        for rule_id in rule_ids:
            rule = registry.get(rule_id)
            if rule:
                rules[rule_id] = rule
                for entry in rule.spec.get("mitre") or []:
                    if entry not in mitre:
                        mitre.append(entry)
                category = category or rule.category
        if alerting:
            decision, active = "alert", 1
        elif suppressed:
            decision, active = "suppressed", 0
        else:
            decision, active = "inactive", 0
        title = top["rule_name"] + (f" (+{len(rule_ids) - 1} related)" if len(rule_ids) > 1 else "")
        keys = {k for s in basis for k in s["event_keys"]}
        summary = _summary(evidence)
        explanation = risk.explain({}, combined, rules)
        connection.execute(
            """UPDATE det_detections SET det_time = ?, last_time = ?, title = ?, primary_rule_id = ?, rule_ids = ?,
                   event_ids = ?, channels = ?, category = ?, mitre = ?, score = ?, severity = ?, severity_rank = ?,
                   confidence = ?, active = ?, decision = ?, signal_count = ?, event_count = ?, user_name = ?,
                   process_name = ?, summary = ?, explanation = ?, sources = ?, suppression_id = ?, updated_at = ?,
                   signal_rules = ?
               WHERE id = ?""",
            (min(s["first_time"] for s in basis), max(s["last_time"] for s in basis), title, top["rule_id"],
             json.dumps(rule_ids), "," + ",".join(event_ids) + ",", json.dumps(channels),
             category or top.get("category") or "Other", json.dumps(mitre), combined["score"], combined["severity"],
             risk.RANK[combined["severity"]], combined["confidence"], active, decision, len(basis), len(keys),
             users[0] if users else None, processes[0] if processes else None, summary,
             json.dumps({"text": explanation, **combined}), json.dumps(sorted({s["source"] for s in basis})),
             (suppressed[0]["suppression_id"] if decision == "suppressed" else None), now,
             json.dumps(sorted({s["rule_id"] for s in signals if s["decision"] not in ("learn_only", "shadow")})),
             det_id))


def _summary(evidence: list[dict[str, Any]]) -> str:
    first = evidence[0] if evidence else {}
    parts = []
    for key, label in (("user.name", "user"), ("process.name", "process"), ("process.parent.name", "parent"),
                       ("service.name", "service"), ("scheduled_task.name", "task"), ("source.ip", "from"),
                       ("registry.path", "registry"), ("file.path", "file"), ("dns.question.name", "dns")):
        if first.get(key):
            value = str(first[key])
            parts.append(f"{label} {value[:80]}")
    return " · ".join(parts[:4])
