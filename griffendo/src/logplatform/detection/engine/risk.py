"""Risk scorer: one score-to-severity mapping used everywhere (engine, API, UI, tests).

Scores are 0-100.  Thresholds are configurable with GRIFFENDO_SEVERITY_THRESHOLDS
("critical,high,medium,low", default "90,70,40,20"); a score below the Low
threshold is Informational.  Elastic's own risk scores (21 / 47 / 73 / 99) fall
in the matching bands, and Wazuh levels are converted to the canonical score of
their band (Informational 10, Low 30, Medium 50, High 75, Critical 95).

Aggregation (several signals in one detection):
    score = max( strongest signal,  100 * (1 - prod(1 - w_i * s_i * decay_i)) )
over *distinct rules* only (the strongest signal per rule), skipping signals
whose evidence events are already counted by a stronger signal, so the same
event matched by several rules is not counted as independent evidence and a
burst of one rule does not compound with itself.  decay_i halves a signal's
contribution every GRIFFENDO_SIGNAL_HALF_LIFE_MINUTES (default 15) of age
relative to the newest signal in the detection.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
CANONICAL = {"Critical": 95, "High": 75, "Medium": 50, "Low": 30, "Informational": 10}
SOURCE_WEIGHT = {"rule": 1.0, "chain": 1.0, "behavior": 0.6}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def thresholds() -> tuple[int, int, int, int]:
    raw = os.getenv("GRIFFENDO_SEVERITY_THRESHOLDS", "90,70,40,20")
    try:
        values = tuple(int(item) for item in raw.split(","))
        if len(values) == 4 and values[0] > values[1] > values[2] > values[3] > 0:
            return values  # type: ignore[return-value]
    except ValueError:
        pass
    return 90, 70, 40, 20


def severity_for(score: float) -> str:
    critical, high, medium, low = thresholds()
    if score >= critical:
        return "Critical"
    if score >= high:
        return "High"
    if score >= medium:
        return "Medium"
    if score >= low:
        return "Low"
    return "Informational"


def band(severity: str) -> tuple[int, int]:
    critical, high, medium, low = thresholds()
    return {"Critical": (critical, 100), "High": (high, critical - 1), "Medium": (medium, high - 1),
            "Low": (low, medium - 1), "Informational": (1, low - 1)}[severity]


def rule_score(severity: str, risk_score: Any = None) -> int:
    """A rule's base score: its own risk score, kept inside its configured severity's band."""
    low, high = band(severity)
    try:
        value = int(risk_score)
    except (TypeError, ValueError):
        return CANONICAL[severity]
    return min(max(value, low), high)


def half_life_minutes() -> float:
    try:
        return max(1.0, float(os.getenv("GRIFFENDO_SIGNAL_HALF_LIFE_MINUTES", "15")))
    except ValueError:
        return 15.0


def combine(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Score, severity, confidence and the contributing signals of one detection."""
    if not signals:
        return {"score": 0.0, "severity": "Informational", "confidence": "low", "contributors": [], "corroborating": []}
    newest = max(_time(s["last_time"]) for s in signals)
    best_per_rule: dict[str, dict[str, Any]] = {}
    for signal in signals:
        current = best_per_rule.get(signal["rule_id"])
        if current is None or signal["score"] > current["score"]:
            best_per_rule[signal["rule_id"]] = signal
    ordered = sorted(best_per_rule.values(), key=lambda s: (-s["score"], s["rule_id"]))
    seen_events: set[str] = set()
    remaining = 1.0
    contributors, corroborating = [], []
    for signal in ordered:
        keys = set(signal.get("event_keys") or [])
        if keys and keys <= seen_events:
            corroborating.append(signal["id"])
            continue
        seen_events |= keys
        age_minutes = max(0.0, (newest - _time(signal["last_time"])).total_seconds() / 60)
        decay = 0.5 ** (age_minutes / half_life_minutes())
        weight = SOURCE_WEIGHT.get(signal.get("source", "rule"), 1.0)
        remaining *= 1 - min(1.0, weight * signal["score"] / 100 * decay)
        contributors.append({"signal_id": signal["id"], "rule_id": signal["rule_id"], "score": signal["score"],
                             "weight": weight, "decay": round(decay, 3)})
    strongest = ordered[0]["score"]
    score = round(max(strongest, 100 * (1 - remaining)), 1)
    confidence = min((s.get("confidence") or "medium" for s in ordered), key=lambda c: CONFIDENCE_RANK.get(c, 1))
    if len(contributors) >= 2 and confidence != "high":
        confidence = "medium" if confidence == "low" else confidence
    return {"score": score, "severity": severity_for(score), "confidence": confidence,
            "contributors": contributors, "corroborating": corroborating}


def explain(detection: dict[str, Any], combined: dict[str, Any], rules: dict[str, Any]) -> str:
    parts = []
    for item in combined["contributors"]:
        rule = rules.get(item["rule_id"])
        name = rule.name if rule else item["rule_id"]
        parts.append(f"{name} ({item['score']:.0f}" + (f", weight {item['weight']}" if item["weight"] != 1 else "")
                     + (f", decayed x{item['decay']}" if item["decay"] < 0.999 else "") + ")")
    critical, high, medium, low = thresholds()
    text = (f"Score {combined['score']:.0f}/100 from " + "; ".join(parts) + ". "
            f"Severity bands: Critical >= {critical}, High >= {high}, Medium >= {medium}, Low >= {low}.")
    if len(combined["contributors"]) > 1:
        text += " Several independent signals for the same entity raise the score (1 - product of (1 - signal))."
    if combined["corroborating"]:
        text += f" {len(combined['corroborating'])} other rule match(es) on the same event(s) are shown as corroboration " \
                "and do not add to the score."
    return text


def _time(value: Any) -> datetime:
    from ...settings import parse_time
    parsed = parse_time(value) if not isinstance(value, datetime) else value
    if parsed is None:
        raise ValueError(f"bad time {value!r}")
    return parsed
