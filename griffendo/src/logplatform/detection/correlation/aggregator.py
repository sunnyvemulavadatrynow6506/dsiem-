"""Episode aggregator: persist signals into continuous correlation episodes (detections).

This module is the write side of the v6 correlation engine.  It replaces v5's
``aggregator.py`` (signals grouped into a cold 30-minute entity bucket) with **open
episodes**: one detection per correlation key that stays open while evidence keeps
arriving, exactly the role a DSIEM backlog plays for a directive.

Public interface is unchanged on purpose (``persist`` / ``recompute``), so the detection
service, the re-evaluation jobs and the suppression code paths keep working; only the
grouping semantics change:

  * a signal is placed by :class:`~.engine.CorrelationEngine` into the episode of its
    correlation key (continuous while the series is unbroken) or a new episode in its
    own time bucket;
  * an existing episode is *updated*, not duplicated: ``first_seen``/``last_seen``,
    ``occurrence_count`` and the contributing signals all grow on the same row;
  * analyst fields (status, verdict, notes, suppression) are **never** touched by a
    recompute, so a later event cannot overwrite an analyst's decision;
  * the score is the noisy-OR over distinct rules plus the documented occurrence
    escalation (:mod:`.risk`), with the explanation stored next to it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from ...settings import iso, utc_now
from ..engine import normalizer, risk as engine_risk
from ..engine.state import epoch
from . import config, identity, risk

# Analyst-owned columns: never written by persist()/recompute().
ANALYST_FIELDS = ("status", "verdict", "status_updated_at", "suppression_id", "assigned_to")


def detection_id(correlation_key: str, bucket: int) -> str:
    return hashlib.sha256(f"{correlation_key}|{bucket}".encode("utf-8")).hexdigest()[:32]


def bucket_seconds() -> int:
    return config.current().bucket_minutes * 60


class EpisodeAggregator:
    """Groups signals into episodes and keeps episode rows consistent."""

    def __init__(self, registry_getter, engine=None):
        self.registry = registry_getter
        self.engine = engine            # correlation.engine.CorrelationEngine

    # ------------------------------------------------------------------ helpers
    def _key_and_bucket(self, signal: dict[str, Any], trigger: dict[str, Any] | None) -> tuple[str, int]:
        """Correlation key + bucket of a signal (recomputed from its own evidence)."""
        events = signal.get("events") or []
        anchor = events[-1] if events else (trigger or {})
        entity = identity.entity_key(anchor)
        root = identity.process_root(anchor, None) if anchor.get("process.entity_id") else None
        key = identity.correlation_key(anchor, entity, root)
        facts_bucket = (signal.get("details") or {}).get("episode_bucket")
        if isinstance(facts_bucket, int):
            return key, facts_bucket
        bucket = int(epoch(anchor.get("@timestamp") or signal.get("last_time") or 0) // bucket_seconds())
        return key, bucket

    def _escalate_rules(self) -> set[str]:
        registry = self.registry()
        return {rule.id for rule in registry.rules.values()
                if (rule.spec.get("correlation") or {}).get("escalate")}

    # ------------------------------------------------------------------ write path
    def persist(self, connection, signals: list[dict[str, Any]], trigger: dict[str, Any] | None,
                origin: str) -> set[str]:
        """Store the signals produced by one event and return the episode ids they touched."""
        if not signals:
            return set()
        touched: set[str] = set()
        now = iso(utc_now())
        for signal in signals:
            if signal.get("retract"):
                row = connection.execute("SELECT detection_id FROM det_signals WHERE id = ?",
                                         (signal["retract"],)).fetchone()
                connection.execute("UPDATE det_signals SET decision = 'retracted' WHERE id = ?",
                                   (signal["retract"],))
                if row and row[0]:
                    touched.add(row[0])
                continue
            key, bucket = self._key_and_bucket(signal, trigger)
            episode = signal.get("episode_id") or detection_id(key, bucket)
            occurrences = int((signal.get("details") or {}).get("occurrences") or 1)
            evidence = [normalizer.summary(ev) for ev in signal["events"]]
            details = dict(signal.get("details") or {})
            details.setdefault("occurrences", occurrences)
            details.setdefault("correlation_key", key)
            details.setdefault("episode_bucket", bucket)
            cursor = connection.execute(
                """INSERT OR IGNORE INTO det_signals(id, rule_id, rule_rev, rule_name, source, kind, first_time,
                       last_time, detection_id, entity_key, score, severity, confidence, decision, suppression_id,
                       event_keys, evidence_json, details_json, origin, created_at, correlation_key, occurrences,
                       episode_bucket)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (signal["id"], signal["rule_id"], signal["rule_rev"], signal["rule"].name, signal["source"],
                 signal["kind"], signal["first_time"], signal["last_time"], episode, key, signal["score"],
                 signal["severity"], signal["confidence"], signal["decision"], signal.get("suppression_id"),
                 json.dumps(signal["event_keys"]), json.dumps(evidence, default=str),
                 json.dumps(details, default=str), origin, now, key, occurrences, bucket))
            if not cursor.rowcount:
                continue
            if signal["decision"] in ("learn_only", "shadow"):
                continue
            touched.add(episode)
            connection.executemany("INSERT OR IGNORE INTO det_event_index(event_key, detection_id) VALUES (?, ?)",
                                   [(k, episode) for k in signal["event_keys"]])
            # An episode row must exist before recompute() can update it.
            connection.execute(
                """INSERT OR IGNORE INTO det_detections(id, entity_key, bucket, hostname, det_time, last_time,
                       title, primary_rule_id, rule_ids, event_ids, channels, category, mitre, score, severity,
                       severity_rank, confidence, active, decision, signal_count, event_count, sources,
                       created_at, updated_at, correlation_key, episode_bucket, occurrence_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '', '[]', NULL, '[]', 0, 'Informational', 4, 'low', 0,
                           'pending', 0, 0, '[]', ?, ?, ?, ?, 0)""",
                (episode, key, bucket, (signal["events"][0] or {}).get("host.name") if signal["events"] else None,
                 signal["first_time"], signal["last_time"], signal["rule"].name, signal["rule_id"], now, now,
                 key, bucket))
        return touched

    # ------------------------------------------------------------------ recompute
    def recompute(self, connection, ids: Iterable[str]) -> int:
        """Refresh each episode's score, severity, counters and explanation from its signals."""
        registry = self.registry()
        escalate_rules = self._escalate_rules()
        changed = 0
        now = iso(utc_now())
        ids = list(dict.fromkeys(ids))
        for start in range(0, len(ids), 300):
            chunk = ids[start:start + 300]
            rows = connection.execute(
                "SELECT id, detection_id, rule_id, rule_rev, rule_name, source, kind, first_time, last_time, score, "
                "severity, confidence, decision, suppression_id, event_keys, evidence_json, occurrences, details_json "
                f"FROM det_signals WHERE detection_id IN ({','.join('?' for _ in chunk)})", chunk).fetchall()
            grouped: dict[str, list[dict[str, Any]]] = {i: [] for i in chunk}
            for row in rows:
                item = dict(row)
                item["event_keys"] = json.loads(item["event_keys"])
                # The occurrence series of a stored signal lives in its details; recompute()
                # reads it back so a re-evaluation reproduces the same counts and score.
                details = json.loads(item.pop("details_json") or "{}")
                item["occurrences"] = details.get("occurrences") or item.get("occurrences") or 1
                item["occurrence_series"] = details.get("occurrence_series") or {}
                grouped[row["detection_id"]].append(item)
            for det_id, signals in grouped.items():
                if self._update(connection, det_id, signals, registry, escalate_rules, now):
                    changed += 1
        return changed

    def _update(self, connection, det_id: str, signals: list[dict[str, Any]], registry,
                escalate_rules: set[str], now: str) -> bool:
        if not signals:
            return False
        existing = connection.execute(
            "SELECT status, verdict, assigned_to, correlation_key, episode_bucket, created_at, title "
            "FROM det_detections WHERE id = ?", (det_id,)).fetchone()

        def active_signal(signal: dict[str, Any]) -> bool:
            rule = registry.get(signal["rule_id"])
            return bool(rule and rule.enabled and rule.rev == signal["rule_rev"])

        alerting = [s for s in signals if s["decision"] == "alert" and active_signal(s)]
        suppressed = [s for s in signals if s["decision"] == "suppressed" and active_signal(s)]
        basis = alerting or suppressed or [s for s in signals if s["decision"] not in ("learn_only", "shadow")] \
            or signals

        # Occurrence counts per rule drive escalation and the "N occurrences" counter.
        # Each signal carries the running count of its occurrence series, and several signals
        # of one series can land in the same episode, so the episode takes the *highest series
        # count per (rule, series start)* instead of adding the running totals together (which
        # would multiply a burst by itself).
        occurrences: dict[str, int] = {}      # risk-effective (bounded) count per rule
        totals: dict[str, int] = {}           # true occurrences per rule, for the analyst
        series_seen: dict[tuple[str, str], tuple[int, int]] = {}
        for signal in basis:
            rule_id = signal["rule_id"]
            series = signal.get("occurrence_series") or {}
            series_start = str(series.get("first_time") or signal.get("first_time"))
            count = max(1, int(series.get("risk_count") or signal.get("occurrences") or 1))
            total = max(1, int(series.get("count") or signal.get("occurrences") or 1))
            slot = (rule_id, series_start)
            previous = series_seen.get(slot, (0, 0))
            if count > previous[0] or total > previous[1]:
                occurrences[rule_id] = occurrences.get(rule_id, 0) - previous[0] + max(count, previous[0])
                totals[rule_id] = totals.get(rule_id, 0) - previous[1] + max(total, previous[1])
                series_seen[slot] = (max(count, previous[0]), max(total, previous[1]))
        occurrences = {rule: max(1, value) for rule, value in occurrences.items()}
        totals = {rule: max(1, value) for rule, value in totals.items()}
        combined = risk.combine(basis, occurrences, escalate_rules)
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
        first_time = min(s["first_time"] for s in basis)
        last_time = max(s["last_time"] for s in basis)

        mitre, category, rules = [], None, {}
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
        distinct = len(rule_ids)
        title = top["rule_name"] + (f" (+{distinct - 1} related)" if distinct > 1 else "")
        keys = {k for s in basis for k in s["event_keys"]}
        event_count = len([k for k in keys if not k.startswith("rate:")])
        total_occurrences = sum(totals.values())
        explanation = risk.explain(combined, rules)
        summary = _summary(evidence, total_occurrences, distinct)
        created = existing["created_at"] if existing else now
        connection.execute(
            """UPDATE det_detections SET det_time = ?, last_time = ?, title = ?, primary_rule_id = ?, rule_ids = ?,
                   event_ids = ?, channels = ?, category = ?, mitre = ?, score = ?, base_score = ?, severity = ?,
                   severity_rank = ?, confidence = ?, active = ?, decision = ?, signal_count = ?, event_count = ?,
                   user_name = ?, process_name = ?, summary = ?, explanation = ?, sources = ?, updated_at = ?,
                   signal_rules = ?, escalation_json = ?, occurrence_count = ?, source_mix = ?
               WHERE id = ?""",
            (first_time, last_time, title, top["rule_id"], json.dumps(rule_ids),
             "," + ",".join(event_ids) + ",", json.dumps(channels), category or top.get("category") or "Other",
             json.dumps(mitre), combined["score"], combined.get("base_score", combined["score"]),
             combined["severity"], engine_risk.RANK[combined["severity"]], combined["confidence"], active, decision,
             len(basis), event_count, users[0] if users else None, processes[0] if processes else None, summary,
             json.dumps({"text": explanation, **combined}), json.dumps(sorted({s["source"] for s in basis})), now,
             json.dumps(sorted({s["rule_id"] for s in signals if s["decision"] not in ("learn_only", "shadow")})),
             json.dumps(combined.get("escalation") or {}), total_occurrences,
             json.dumps(sorted({s["source"] for s in basis})), det_id))
        return True


def _summary(evidence: list[dict[str, Any]], occurrences: int, distinct: int) -> str:
    """One line of context: who/what, and how much of it."""
    first = evidence[0] if evidence else {}
    parts = []
    for key, label in (("user.name", "user"), ("process.name", "process"), ("process.parent.name", "parent"),
                       ("service.name", "service"), ("scheduled_task.name", "task"), ("source.ip", "from"),
                       ("registry.path", "registry"), ("file.path", "file"), ("dns.question.name", "dns")):
        if first.get(key):
            parts.append(f"{label} {str(first[key])[:80]}")
    scope = []
    if occurrences > 1:
        scope.append(f"{occurrences} occurrences")
    if distinct > 1:
        scope.append(f"{distinct} correlated rules")
    text = " · ".join(parts[:4])
    if scope:
        text = (text + " · " if text else "") + " · ".join(scope)
    return text
