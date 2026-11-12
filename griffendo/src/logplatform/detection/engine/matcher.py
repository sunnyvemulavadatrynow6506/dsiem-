"""Rule matcher: deterministic rules evaluated against normalized events.

Kinds handled here:
  single     one event satisfies the condition
  threshold  N matching events with the same group-field values inside a sliding window
  sequence   ordered steps (EQL ``sequence by ... with maxspan``), joined on field values, optional ``until``
  new_terms  first occurrence of a field-value combination within the history window
  wazuh      the Wazuh rule tree (parent/child, if_group, frequency/timeframe/same_field, if_fts)

Events may arrive out of time order (historical backfill reads newest first), so
threshold and sequence state is kept time-sorted and assembled around each new event.
Events used by a completed threshold or sequence are consumed (not reused by the same
rule), as Elasticsearch does.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from . import conditions
from .normalizer import get
from .state import StateManager, epoch

MAX_EVIDENCE = 25


def signal_id(rule_id: str, rev: str, keys: list[str], extra: str = "") -> str:
    material = f"{rule_id}|{rev}|{'|'.join(sorted(keys))}|{extra}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def draft(rule, events: list[dict[str, Any]], source: str = "rule", extra: str = "",
          details: dict[str, Any] | None = None, decision: str = "alert", score: float | None = None) -> dict[str, Any]:
    keys = [ev["_key"] for ev in events]
    times = sorted(ev["@timestamp"] for ev in events)
    return {"id": signal_id(rule.id, rule.rev, keys, extra), "rule": rule, "rule_id": rule.id, "rule_rev": rule.rev,
            "source": source, "kind": rule.kind, "events": events[:MAX_EVIDENCE], "event_keys": keys,
            "first_time": times[0], "last_time": times[-1], "event_time": times[-1],
            "score": rule.score if score is None else score, "severity": rule.severity,
            "confidence": rule.confidence, "details": details or {}, "decision": decision}


def _key(ev: dict[str, Any], fields: list[str]) -> tuple | None:
    values = []
    for field in fields:
        value = get(ev, field)
        if value is None:
            return None
        if isinstance(value, list):
            value = tuple(sorted(str(item).lower() for item in value))
        else:
            value = str(value).lower()
        values.append(value)
    return tuple(values)


class Matcher:
    def __init__(self, state: StateManager, terms):
        self.state = state
        self.terms = terms            # model_store.TermStore

    # ------------------------------------------------------------------ dispatch
    def evaluate(self, rule, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        kind = rule.kind
        if kind == "single":
            if rule.predicate(ev):
                return [draft(rule, [ev], details={"matched": conditions.explain(rule.spec["condition"], ev)})]
            return []
        if kind == "threshold":
            return self._threshold(rule, ev, t)
        if kind == "sequence":
            return self._sequence(rule, ev, t)
        if kind == "new_terms":
            return self._new_terms(rule, ev, t)
        return []

    # ------------------------------------------------------------------ threshold
    def _threshold(self, rule, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        if not rule.predicate(ev):
            return []
        spec = rule.spec["threshold"]
        by = spec.get("by") or []
        key = _key(ev, by) if by else ()
        if key is None:
            return []
        span = float(spec["window_seconds"])
        family = self.state.family(f"thr:{rule.id}:{rule.rev}", span * 2)
        window = family.add(key, t, ev)
        nearby = [(time_, item) for time_, item in window.between(t - span, t + span)
                  if not self.state.is_used(rule.id, item["_key"])]
        count = spec["count"]
        # Any window of length `span` containing t with >= count unused events?
        times = [time_ for time_, _ in nearby]
        for start_index in range(len(times)):
            end_limit = times[start_index] + span
            members = [item for time_, item in nearby[start_index:] if time_ <= end_limit]
            if len(members) >= count and any(item is ev for item in members):
                chosen = members[:max(count, len(members))]
                self.state.mark_used(rule.id, [item["_key"] for item in chosen])
                group = dict(zip(by, key)) if by else {}
                return [draft(rule, chosen, extra=json.dumps(group, sort_keys=True),
                              details={"threshold": {"count": len(chosen), "required": count,
                                                     "window_seconds": int(span), "group": group},
                                       "matched": conditions.explain(rule.spec["condition"], ev)})]
        return []

    # ------------------------------------------------------------------ sequence
    def _sequence(self, rule, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        maxspan = float(rule.spec.get("maxspan") or 3600)
        family = self.state.family(f"seq:{rule.id}:{rule.rev}", maxspan * 2)
        steps = rule.steps
        first_of = [i if i == 0 or steps[i] is not steps[i - 1] else None for i in range(len(steps))]
        for i in range(len(steps)):
            if first_of[i] is None:
                first_of[i] = first_of[i - 1]
        if rule.until and rule.until["predicate"](ev):
            key = _key(ev, rule.until["by"]) if rule.until["by"] else ()
            if key is not None:
                family.add(("until", key), t, ev)
        matched: list[tuple[int, tuple]] = []
        for index, step in enumerate(steps):
            if first_of[index] != index:
                continue
            if step["predicate"](ev):
                key = _key(ev, step["by"]) if step["by"] else ()
                if key is not None:
                    family.add((index, key), t, ev)
                    matched.append((index, key))
        for group_index, key in matched:
            positions = [i for i in range(len(steps)) if first_of[i] == group_index]
            for position in positions:
                chain = self._assemble(rule, family, first_of, position, key, ev, t, maxspan)
                if not chain:
                    continue
                keys = [item["_key"] for item in chain]
                self.state.mark_used(rule.id, keys)
                join = dict(zip(steps[0]["by"], key)) if steps[0]["by"] else {}
                return [draft(rule, chain, details={
                    "sequence": [{"step": i + 1, "time": item["@timestamp"], "event_id": item.get("event.code"),
                                  "channel": item.get("winlog.channel")} for i, item in enumerate(chain)],
                    "join": join, "maxspan_seconds": int(maxspan)})]
        return []

    def _assemble(self, rule, family, first_of, index: int, key: tuple, ev: dict[str, Any], t: float,
                  maxspan: float):
        steps = rule.steps
        chain: list[Any] = [None] * len(steps)
        chain[index] = (t, ev)
        used_keys = {ev["_key"]}

        def options(step_index: int) -> list[tuple[float, Any]]:
            window = family.get((first_of[step_index], key))
            if window is None:
                return []
            return [(time_, item) for time_, item in window.between(t - maxspan, t + maxspan)
                    if item["_key"] not in used_keys and not self.state.is_used(rule.id, item["_key"])]

        # Earlier steps take the latest event before the next step, later steps the earliest after the
        # previous one: this minimises the span, so a chain is found whenever one exists.
        for step_index in range(index - 1, -1, -1):
            limit = chain[step_index + 1][0]
            found = [option for option in options(step_index) if option[0] <= limit]
            if not found:
                return None
            chosen = max(found, key=lambda option: option[0])
            chain[step_index] = chosen
            used_keys.add(chosen[1]["_key"])
        for step_index in range(index + 1, len(steps)):
            limit = chain[step_index - 1][0]
            found = [option for option in options(step_index) if option[0] >= limit]
            if not found:
                return None
            chosen = min(found, key=lambda option: option[0])
            chain[step_index] = chosen
            used_keys.add(chosen[1]["_key"])
        first, last = chain[0][0], chain[-1][0]
        if last - first > maxspan:
            return None
        if rule.until:
            window = family.get(("until", key if rule.until["by"] else ()))
            if window and any(first < time_ < last for time_, _ in window.between(first, last)):
                return None
        return [item for _, item in chain]

    # ------------------------------------------------------------------ new terms
    def _new_terms(self, rule, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        if not rule.predicate(ev):
            return []
        fields = rule.spec["new_terms"].get("fields") or []
        values = []
        for field in fields:
            value = get(ev, field)
            if value is None:
                return []
            values.append(sorted(str(v).lower() for v in value) if isinstance(value, list) else str(value).lower())
        term = json.dumps(values, separators=(",", ":"))
        history = float(rule.spec["new_terms"].get("history_days", 7)) * 86400
        verdict = self.terms.check(rule.id, term, t, history)
        if not verdict["new"]:
            return []
        details = {"new_terms": {"fields": fields, "values": values, "history_days": rule.spec["new_terms"]
                                 .get("history_days", 7), "history_covered": verdict["covered"]},
                   "matched": conditions.explain(rule.spec["condition"], ev)}
        if verdict.get("retract"):
            details["supersedes"] = verdict["retract"]
        signal = draft(rule, [ev], extra=term, details=details,
                       decision="alert" if verdict["covered"] else "learn_only")
        self.terms.remember_signal(rule.id, term, signal["id"])
        if verdict.get("retract"):
            signal["retract"] = verdict["retract"]
        return [signal]


class WazuhTree:
    """Wazuh rule-tree evaluation: one final rule per event (the deepest match), alerts at level >= 3."""

    def __init__(self, rules: list, state: StateManager, terms):
        self.state, self.terms = state, terms
        self.rules = {rule.spec["wazuh"]["wazuh_id"]: rule for rule in rules}
        self.children: dict[str, list] = {}
        groups: dict[str, list] = {}
        for rule in rules:
            for group in rule.spec["wazuh"].get("groups") or []:
                groups.setdefault(group, []).append(rule)
        roots = []
        for rule in rules:
            w = rule.spec["wazuh"]
            parents = [self.rules[p] for p in (w.get("if_sid") or []) + (w.get("if_matched_sid") or []) if p in self.rules]
            for group in (w.get("if_group") or []) + (w.get("if_matched_group") or []):
                parents += [member for member in groups.get(group, []) if member is not rule]
            if not parents and not (w.get("if_sid") or w.get("if_matched_sid") or w.get("if_group")
                                    or w.get("if_matched_group")):
                roots.append(rule)
            for parent in parents:
                bucket = self.children.setdefault(parent.id, [])
                if rule not in bucket:
                    bucket.append(rule)
        for parent_id, bucket in self.children.items():
            # Frequency (if_matched_*) children are tried first, then file order (as Wazuh's rule tree).
            bucket.sort(key=lambda r: (0 if r.spec["wazuh"].get("frequency") else 1, r.spec["wazuh"].get("order", 0)))
        self.roots = sorted(roots, key=lambda r: r.spec["wazuh"].get("order", 0))

    def evaluate(self, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        for root in self.roots:
            if self._matches(root, ev, t, None):
                final, path, extra = self._descend(root, ev, t, [root])
                if final.alerting and final.enabled:
                    details = {"wazuh_path": [{"id": r.spec["wazuh"]["wazuh_id"], "level": r.spec["wazuh"]["level"],
                                               "description": r.name} for r in path]}
                    events = [ev]
                    decision = "alert"
                    if extra.get("frequency"):
                        details["frequency"] = extra["frequency"]
                        events = extra["events"]
                    if extra.get("fts") is not None:
                        details["first_time_seen"] = extra["fts"]
                        if not extra["fts"]["covered"]:
                            decision = "learn_only"
                    return [draft(final, events, details=details, decision=decision,
                                  extra="freq" if extra.get("frequency") else "")]
                return []
        return []

    def _descend(self, node, ev, t, path):
        extra: dict[str, Any] = {}
        for child in self.children.get(node.id, []):
            result = self._matches(child, ev, t, node)
            if result:
                if isinstance(result, dict):
                    extra = result
                final, deeper_path, deeper_extra = self._descend(child, ev, t, path + [child])
                return final, deeper_path, deeper_extra or extra
        return node, path, extra

    def _matches(self, rule, ev, t, parent) -> bool | dict:
        if not rule.enabled:
            return False
        w = rule.spec["wazuh"]
        if not rule.predicate(ev):
            return False
        if w.get("if_fts"):
            term = json.dumps([str(get(ev, "user.name") or "").lower(), str(get(ev, "source.domain") or "").lower()])
            verdict = self.terms.check(rule.id, term, t, 365 * 86400)
            if not verdict["new"]:
                return False
            return {"fts": {"key": json.loads(term), "covered": verdict["covered"]}}
        if not w.get("frequency"):
            return True
        same = [f.replace("win.eventdata.", "winlog.event_data.") for f in w.get("same_field") or []]
        key = _key(ev, same) if same else ()
        if key is None:
            return False
        timeframe = float(w.get("timeframe") or 120)
        family = self.state.family(f"waz:{rule.id}", timeframe * 2)
        window = family.add(key, t, ev)
        recent = [(time_, item) for time_, item in window.between(t - timeframe, t)
                  if not self.state.is_used(rule.id, item["_key"])]
        if len(recent) >= int(w["frequency"]):
            events = [item for _, item in recent]
            self.state.mark_used(rule.id, [item["_key"] for item in events])
            return {"frequency": {"count": len(events), "required": int(w["frequency"]),
                                  "timeframe_seconds": int(timeframe),
                                  "same_fields": dict(zip(same, key)) if same else {}},
                    "events": events}
        return False


_ = Callable
