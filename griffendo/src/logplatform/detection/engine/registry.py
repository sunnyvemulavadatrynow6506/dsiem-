"""Rule registry: loads one module per rule (rules/index.py), custom rules, and per-rule switches.

A rule module exposes ``RULE`` (a plain dict, see rules/README in docs/REPORT.md).  The
registry validates it, compiles its conditions, computes its revision (a hash of
everything that decides what it matches) and indexes it by (channel, Event ID), so an
event is only evaluated against the rules that can possibly match it.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import threading
from typing import Any, Callable, Iterable

from . import conditions, risk

KINDS = {"single", "threshold", "sequence", "new_terms", "wazuh", "chain", "behavior"}
ORIGINS = {"griffendo": "Griffendo built-in", "elastic": "Elastic detection-rules (imported)",
           "wazuh": "Wazuh ruleset (imported)", "custom": "User-defined", "catalog": "Griffendo v2-v4 catalog"}
_MATCH_KEYS = ("kind", "condition", "sources", "steps", "maxspan", "until", "threshold", "new_terms", "wazuh",
               "chain", "behavior")


def revision(spec: dict[str, Any]) -> str:
    material = {key: spec.get(key) for key in _MATCH_KEYS if spec.get(key) is not None}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
                          .encode("utf-8")).hexdigest()[:12]


class RuleError(ValueError):
    pass


class Rule:
    __slots__ = ("spec", "id", "name", "kind", "origin", "severity", "risk_score", "score", "confidence", "category",
                 "rev", "enabled", "predicate", "steps", "sources", "default_enabled", "protected", "until",
                 "alerting", "module")

    def __init__(self, spec: dict[str, Any], module: str | None = None):
        problems = validate_spec(spec)
        if problems:
            raise RuleError(f"{spec.get('id')}: " + "; ".join(problems[:5]))
        self.spec = spec
        self.module = module
        self.id = spec["id"]
        self.name = spec["name"]
        self.kind = spec["kind"]
        self.origin = spec.get("origin", "griffendo")
        self.severity = spec["severity"]
        self.risk_score = spec.get("risk_score")
        self.score = risk.rule_score(self.severity, self.risk_score)
        self.confidence = spec.get("confidence", "high")
        self.category = spec.get("category") or "Other"
        self.rev = revision(spec)
        self.default_enabled = bool(spec.get("enabled", True))
        self.enabled = self.default_enabled
        self.protected = bool(spec.get("protected"))
        self.alerting = True
        self.predicate: Callable[[dict[str, Any]], bool] | None = None
        self.steps: list[dict[str, Any]] = []
        self.until = None
        self.sources = list(spec.get("sources") or [])
        if self.kind in ("single", "threshold", "new_terms"):
            self.predicate = conditions.compile_condition(spec["condition"])
        elif self.kind == "sequence":
            expanded = []
            for step in spec["steps"]:
                compiled = {"predicate": conditions.compile_condition(step["condition"]), "by": step.get("by") or [],
                            "sources": step.get("sources") or []}
                expanded.extend([compiled] * max(1, int(step.get("runs", 1))))
            self.steps = expanded
            if spec.get("until"):
                self.until = {"predicate": conditions.compile_condition(spec["until"]["condition"]),
                              "by": spec["until"].get("by") or [], "sources": spec["until"].get("sources") or []}
            self.sources = [source for step in spec["steps"] for source in (step.get("sources") or [])]
        elif self.kind == "wazuh":
            self.predicate = conditions.compile_condition(spec["wazuh"]["condition"])
            self.alerting = spec["wazuh"]["level"] >= 3
            self.protected = self.protected or not self.alerting
        elif self.kind == "chain":
            self.steps = [{"name": step["name"], "predicate": conditions.compile_condition(step["condition"]),
                           "relation": step.get("relation"), "sources": step.get("sources") or []}
                          for step in spec["chain"]["steps"]]
            self.sources = [source for step in spec["chain"]["steps"] for source in (step.get("sources") or [])]

    def public(self) -> dict[str, Any]:
        spec = self.spec
        return {
            "rule_id": self.id, "name": self.name, "kind": self.kind, "origin": self.origin,
            "origin_label": ORIGINS.get(self.origin, self.origin), "severity": self.severity, "score": self.score,
            "confidence": self.confidence, "category": self.category, "description": spec.get("description", ""),
            "enabled": self.enabled, "default_enabled": self.default_enabled, "protected": self.protected,
            "alerting": self.alerting, "rev": self.rev, "sources": self.sources, "mitre": spec.get("mitre") or [],
            "support": spec.get("support") or {}, "source": spec.get("source") or {},
            "modifications": spec.get("modifications") or [], "investigation": spec.get("investigation", ""),
            "false_positives": spec.get("false_positives") or [], "required_fields": spec.get("required_fields") or [],
            "correlation": _correlation_summary(spec), "module": self.module,
            "created_at": spec.get("created_at"), "modified_at": spec.get("modified_at"),
            "verified": self.origin != "custom",
        }


def _correlation_summary(spec: dict[str, Any]) -> dict[str, Any] | None:
    kind = spec["kind"]
    if kind == "sequence":
        return {"type": "sequence", "steps": len(spec["steps"]), "maxspan_seconds": spec.get("maxspan"),
                "join_fields": sorted({f for step in spec["steps"] for f in (step.get("by") or [])})}
    if kind == "threshold":
        return {"type": "threshold", **spec["threshold"]}
    if kind == "new_terms":
        return {"type": "new_terms", **spec["new_terms"]}
    if kind == "chain":
        return {"type": "chain", "steps": [s["name"] for s in spec["chain"]["steps"]],
                "window_seconds": spec["chain"].get("window_seconds")}
    if kind == "wazuh":
        w = spec["wazuh"]
        if w.get("frequency"):
            return {"type": "frequency", "count": w["frequency"], "window_seconds": w.get("timeframe"),
                    "same_fields": w.get("same_field") or []}
    return None


def validate_spec(spec: dict[str, Any], field_ok: Callable[[str], str | None] | None = None) -> list[str]:
    problems: list[str] = []
    for key in ("id", "name", "kind", "severity"):
        if not spec.get(key):
            problems.append(f"missing '{key}'")
    if spec.get("kind") not in KINDS:
        problems.append(f"unknown kind {spec.get('kind')!r}")
    if spec.get("severity") not in risk.SEVERITIES:
        problems.append(f"severity must be one of {', '.join(risk.SEVERITIES)}")
    kind = spec.get("kind")
    if kind in ("single", "threshold", "new_terms"):
        problems += conditions.validate(spec.get("condition"), field_ok)
    if kind == "threshold":
        threshold = spec.get("threshold") or {}
        if not isinstance(threshold.get("count"), int) or threshold["count"] < 1:
            problems.append("threshold count must be a positive whole number")
        if not isinstance(threshold.get("window_seconds"), int) or not 1 <= threshold["window_seconds"] <= 7 * 86400:
            problems.append("threshold window must be between 1 second and 7 days")
    if kind == "sequence":
        steps = spec.get("steps") or []
        if not steps or (len(steps) < 2 and int(steps[0].get("runs", 1)) < 2):
            problems.append("a sequence needs at least two steps")
        for step in steps:
            problems += conditions.validate(step.get("condition"), field_ok)
        if not isinstance(spec.get("maxspan"), int) or not 1 <= spec["maxspan"] <= 7 * 86400:
            problems.append("sequence maxspan must be between 1 second and 7 days")
    if kind == "chain":
        for step in (spec.get("chain") or {}).get("steps") or []:
            problems += conditions.validate(step.get("condition"), field_ok)
    if kind == "wazuh":
        problems += conditions.validate((spec.get("wazuh") or {}).get("condition"), field_ok)
    return problems


def load_modules(names: Iterable[str], package: str = "logplatform.detection.rules") -> tuple[list[Rule], list[str]]:
    rules, errors = [], []
    for name in names:
        try:
            module = importlib.import_module(f"{package}.{name}")
            rules.append(Rule(module.RULE, module=name))
        except Exception as error:  # a broken rule file must not stop the engine
            errors.append(f"{name}: {error}")
    return rules, errors


class Registry:
    """The loaded rules, their switches and the (channel, Event ID) index."""

    def __init__(self, rules: list[Rule], errors: list[str] | None = None):
        self.lock = threading.RLock()
        self.errors = list(errors or [])
        self.rules: dict[str, Rule] = {}
        self.retired: dict[str, dict[str, Any]] = {}
        self.version = 0
        for rule in rules:
            if rule.id in self.rules:
                self.errors.append(f"duplicate rule id {rule.id} ({rule.module}) ignored")
                continue
            self.rules[rule.id] = rule
        self.rebuild()

    def rebuild(self) -> None:
        with self.lock:
            index: dict[tuple[str, int | None], list[Rule]] = {}
            wazuh: list[Rule] = []
            behavior: list[Rule] = []
            for rule in self.rules.values():
                if rule.kind == "wazuh":
                    wazuh.append(rule)
                    continue
                if rule.kind == "behavior":
                    behavior.append(rule)
                    continue
                for source in rule.sources:
                    channel = source["channel"].lower()
                    ids = source.get("event_ids") or [None]
                    for eid in ids:
                        bucket = index.setdefault((channel, eid), [])
                        if rule not in bucket:
                            bucket.append(rule)
            self.index = index
            self.wazuh = sorted(wazuh, key=lambda r: r.spec["wazuh"].get("order", 0))
            self.behavior = behavior
            self.version += 1

    def candidates(self, channel: str | None, event_id: int | None) -> list[Rule]:
        channel_l = (channel or "").lower()
        specific = self.index.get((channel_l, event_id), [])
        wide = self.index.get((channel_l, None), [])
        if not wide:
            return [rule for rule in specific if rule.enabled]
        return [rule for rule in specific + [r for r in wide if r not in specific] if rule.enabled]

    def get(self, rule_id: str) -> Rule | None:
        return self.rules.get(rule_id)

    def channels(self, enabled_only: bool = True) -> dict[str, int]:
        # Cached per registry version: the receiver checks every incoming event's channel against
        # this list, and walking 1,456 rules per event made ingestion about 5x slower in v5.0.
        cached = getattr(self, "_channels_cache", None)
        if cached is not None and cached[0] == (self.version, enabled_only):
            return dict(cached[1])
        counts = self._count_channels(enabled_only)
        self._channels_cache = ((self.version, enabled_only), counts)
        return dict(counts)

    def _count_channels(self, enabled_only: bool) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rule in self.rules.values():
            if enabled_only and not (rule.enabled and rule.alerting):
                continue
            names = {source["channel"] for source in rule.sources}
            if rule.kind == "wazuh":
                names = set(rule.spec["wazuh"].get("channels") or [])
            for name in names:
                counts[name] = counts.get(name, 0) + 1
        return counts

    def replace(self, rule: Rule) -> None:
        with self.lock:
            self.rules[rule.id] = rule
            self.rebuild()

    def remove(self, rule_id: str) -> Rule | None:
        with self.lock:
            rule = self.rules.pop(rule_id, None)
            if rule:
                self.retired[rule_id] = rule.public()
            self.rebuild()
            return rule
