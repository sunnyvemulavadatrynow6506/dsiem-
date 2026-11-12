"""Risk escalation: how repetition and correlation strength change an episode's score.

The v5 scorer (``engine/risk.py``) is reused unchanged: it combines the *distinct rules*
contributing to a detection with a noisy-OR, decays older signals and never lets one rule
compound with itself.  It is correct for "how bad is this set of findings", but it has one
structural blind spot that the v6 engine fixes here:

    **It cannot see repetition.**  A brute-force burst and a single typo produce the same
    set of findings, so they score the same.  DSIEM expresses this through ``occurrence``
    and backlog risk escalation.

The rule below is deliberately conservative and fully explainable:

    escalation = min(cap, per_decade * log10(occurrences))     occurrences >= 1
    episode_score = base_score + escalation                    capped at 100

* ``per_decade`` (default 4) means 10 occurrences add 4 points, 100 add 8, 1000 add 12.
  A logarithmic curve keeps a long brute-force burst meaningful without letting event
  volume dominate the score.
* ``cap`` (default 12) bounds the bonus, so escalation alone never promotes a Low finding
  to Critical.
* Escalation applies **only** to rules that declare ``"correlation": {"escalate": true}``.
  A rule that is already a "one event is enough" indicator does not escalate just because
  it fired many times; volume-only rules (failed logons, error events) opt in, and their
  rule definition documents it.

Every component is returned with the score so the detection detail page, the API and the
tests can all show *why* a score is what it is — no hidden arithmetic.
"""
from __future__ import annotations

import math
from typing import Any

from . import config


def base_blocks(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from ..engine import risk
    combined = risk.combine(signals)
    return combined.get("contributors") or []


def escalate(rule_score: float, occurrences: int, *, enabled: bool = True,
             cfg: config.CorrelationConfig | None = None) -> dict[str, Any]:
    """The escalation component for one rule's occurrence count."""
    settings = cfg or config.current()
    occurrences = max(1, int(occurrences))
    bonus = 0.0
    if enabled and settings.occurrence_escalation and occurrences > 1:
        bonus = settings.escalation_per_decade * math.log10(occurrences)
        bonus = min(bonus, settings.occurrence_escalation_max)
    return {"enabled": bool(enabled and settings.occurrence_escalation), "occurrences": occurrences,
            "bonus": round(bonus, 2), "cap": settings.occurrence_escalation_max,
            "per_decade": settings.escalation_per_decade, "applied": round(bonus, 2) > 0}


def combine(signals: list[dict[str, Any]], occurrences: dict[str, int] | None = None,
            escalate_rules: set[str] | None = None,
            cfg: config.CorrelationConfig | None = None) -> dict[str, Any]:
    """Score an episode: the v5 noisy-OR over distinct rules, plus bounded escalation.

    ``occurrences`` maps rule id -> number of times that rule matched in the episode;
    ``escalate_rules`` lists the rules allowed to escalate (from their rule definition).
    """
    from ..engine import risk
    settings = cfg or config.current()
    combined = risk.combine(signals)
    occurrences = occurrences or {}
    escalate_rules = escalate_rules or set()
    escalation = []
    total_bonus = 0.0
    for contributor in combined["contributors"]:
        rule_id = contributor["rule_id"]
        count = occurrences.get(rule_id, 1)
        part = escalate(contributor["score"], count, enabled=rule_id in escalate_rules, cfg=settings)
        part["rule_id"] = rule_id
        if part["applied"]:
            total_bonus += part["bonus"]
            escalation.append(part)
    base = combined["score"]
    total_bonus = min(total_bonus, settings.occurrence_escalation_max)
    score = round(min(100.0, base + total_bonus), 1)
    if total_bonus:
        # Escalation may move the severity band; recompute it from the escalated score.
        combined["severity"] = risk.severity_for(score)
    combined["score"] = score
    combined["base_score"] = base
    combined["escalation"] = {"applied": round(total_bonus, 2), "cap": settings.occurrence_escalation_max,
                              "parts": escalation}
    combined["occurrences"] = {c["rule_id"]: occurrences.get(c["rule_id"], 1) for c in combined["contributors"]}
    return combined


def explain(combined: dict[str, Any], rules: dict[str, Any]) -> str:
    """Plain-language description of the episode score, for the UI and the API."""
    from ..engine import risk
    text = risk.explain({}, {**combined, "score": combined.get("base_score", combined["score"]),
                             "contributors": combined["contributors"],
                             "corroborating": combined.get("corroborating", [])}, rules)
    escalation = combined.get("escalation") or {}
    if escalation.get("applied"):
        parts = "; ".join(f"{item['rule_id']} x{item['occurrences']} (+{item['bonus']:.1f})"
                          for item in escalation["parts"])
        text += (f" Repetition adds {escalation['applied']:.1f} points (bounded at "
                 f"{escalation['cap']:.0f}, logarithmic: {parts}), so this detection scores "
                 f"{combined['score']:.0f}/100 instead of {combined.get('base_score', 0):.0f}.")
    return text
