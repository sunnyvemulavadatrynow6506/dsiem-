"""DSIEM directive stages: sequential escalation of one indicator, rebuilt for Griffendo.

This module ports the one part of DSIEM's directive model that the first pass of the v6
engine did not reproduce: **stages**.

In DSIEM (`internal/pkg/dsiem/siem/backlog.go`), a directive rule carries a ``stage``, an
``occurrence`` count, a ``timeout`` and a ``reliability``.  A backlog starts at stage 1 and
walks up the directive's rules in order:

  * stage 1: fire once -> the alarm is created (low reliability, low risk);
  * stage 2: fire again `occurrence` times -> `increaseStage()` -> same alarm, higher
    reliability -> higher risk;
  * stage 3: … and so on to the highest stage, then the backlog is deleted.

`isStageReachMaxEvtCount` compares the events accumulated for the current stage against that
stage's ``occurrence``; `isExpired` closes the backlog when the current stage has waited
longer than its ``timeout``.  The alarm's risk is
``priority * reliability * assetValue / 25`` (`calcRisk`), clamped to 0-10 and classified
Low/Medium/High.

The effect an analyst sees is **escalation over time**: "one failed logon" (Low) becomes
"3 failed logons" (Medium) becomes "10 000 failed logons" (High) on the *same* detection,
instead of three unrelated detections or one flat score.

Mapping onto Griffendo's v6 engine
----------------------------------
A Griffendo rule opts in with the same vocabulary it already uses for `correlation`:

    'correlation': {
        'stages': [
            {'occurrence': 1,     'timeout_seconds': 300,  'reliability': 1},
            {'occurrence': 5,     'timeout_seconds': 1800, 'reliability': 5},
            {'occurrence': 50,    'timeout_seconds': 7200, 'reliability': 9},
        ],
    }

* ``occurrence`` is the *cumulative* number of occurrences of the series required to reach
  that stage (DSIEM's per-stage counts are cumulative in practice because a backlog keeps
  all of its events, so the port uses cumulative counts - it is equivalent and simpler to
  reason about, and it is documented here because it is the one deliberate deviation).
* ``timeout_seconds`` is how long the stage may wait before it expires.  An expired series
  does not lose evidence: the detection keeps what it has and the stage marker is recorded.
* ``reliability`` 1-10 maps to DSIEM's reliability scale and is turned into a score by the
  same formula, so a stage-3 brute force outranks a stage-1 one by the ratio DSIEM would use.

Reliability -> score
--------------------
DSIEM: ``risk = priority * reliability * assetValue / 25``, ``assetValue`` = 5 when unknown.
With priority 10 and asset 5 that is ``reliability * 2``, i.e. reliability 1-10 -> 2-20 on
DSIEM's 0-10 risk scale, which Griffendo rescales to its 0-100 scale by ``* 5``:
``score = reliability * 10``.  The scale is stated here rather than buried, and the value is
still clamped inside the rule's own severity band, so a stage can never silently jump a
severity class the rule's author did not choose.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_STAGES = 10


@dataclass(frozen=True)
class Stage:
    """One escalation stage of a rule."""

    index: int              # 1-based, as in DSIEM
    occurrence: int         # cumulative occurrences needed to reach this stage
    timeout_seconds: float  # how long this stage may wait
    reliability: int        # 1-10, DSIEM's reliability scale

    def score(self) -> int:
        """This stage's score on Griffendo's 0-100 scale (see the module docstring)."""
        return max(1, min(100, int(self.reliability) * 10))

    def public(self) -> dict[str, Any]:
        return {"stage": self.index, "occurrence": self.occurrence,
                "timeout_seconds": int(self.timeout_seconds), "reliability": self.reliability,
                "score": self.score()}


def parse(spec: dict[str, Any] | None) -> list[Stage]:
    """Validate and normalise a rule's ``correlation.stages`` block.

    Raises ``ValueError`` with a message an analyst can act on, because this is authored by
    users through the rule editor, not generated.
    """
    if not spec:
        return []
    raw = spec.get("stages")
    if not raw:
        return []
    if not isinstance(raw, list):
        raise ValueError("correlation.stages must be a list")
    if len(raw) > MAX_STAGES:
        raise ValueError(f"at most {MAX_STAGES} stages are supported")
    stages: list[Stage] = []
    previous = 0
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"stage {index} must be an object")
        try:
            occurrence = int(item.get("occurrence", 0))
            timeout = float(item.get("timeout_seconds", 300))
            reliability = int(item.get("reliability", index))
        except (TypeError, ValueError):
            raise ValueError(f"stage {index}: occurrence/timeout_seconds/reliability must be numbers")
        if occurrence < 1:
            raise ValueError(f"stage {index}: occurrence must be 1 or more")
        if occurrence < previous:
            raise ValueError(f"stage {index}: occurrence must not decrease (stages escalate)")
        if not 1 <= reliability <= 10:
            raise ValueError(f"stage {index}: reliability must be 1-10 (DSIEM's scale)")
        if not 1 <= timeout <= 7 * 86400:
            raise ValueError(f"stage {index}: timeout_seconds must be 1..604800")
        stages.append(Stage(index=index, occurrence=occurrence, timeout_seconds=timeout,
                            reliability=reliability))
        previous = occurrence
    if stages and stages[0].occurrence != 1:
        # Stage 1 must be reachable by the first occurrence, otherwise the indicator could
        # never alert at all and the rule would look broken.
        raise ValueError("stage 1: occurrence must be 1 (the first match must reach stage 1)")
    return stages


def evaluate(stages: list[Stage], occurrences: int, elapsed: float) -> dict[str, Any]:
    """Which stage a series is on, given its occurrence count and age.

    ``elapsed`` is the time since the series started (seconds).  Returns the current stage,
    the next one (if any), whether the current stage has expired, and the score to use.
    """
    if not stages:
        return {"staged": False}
    current = stages[0]
    for stage in stages:
        if occurrences >= stage.occurrence:
            current = stage
        else:
            break
    following = next((s for s in stages if s.occurrence > current.occurrence), None)
    expired = bool(current.timeout_seconds and elapsed > current.timeout_seconds
                   and (following is None or occurrences < following.occurrence))
    return {"staged": True, "stage": current.index, "stages": len(stages),
            "reached_at": current.occurrence, "reliability": current.reliability,
            "score": current.score(), "expired": expired,
            "next_occurrence": following.occurrence if following else None,
            "next_reliability": following.reliability if following else None,
            "current": current.public(),
            "history": [s.public() for s in stages]}


def explain(result: dict[str, Any]) -> str:
    """Plain-language stage explanation for the detection detail view."""
    if not result.get("staged"):
        return ""
    text = (f"Stage {result['stage']} of {result['stages']}: {result['reached_at']} occurrence(s) "
            f"reached, reliability {result['reliability']}/10 -> stage score {result['score']}.")
    if result.get("next_occurrence"):
        text += (f" Reaching {result['next_occurrence']} occurrences escalates to stage "
                 f"{result['stage'] + 1} (reliability {result['next_reliability']}/10).")
    if result.get("expired"):
        text += " The stage timed out before escalating; evidence is kept and the series restarts."
    return text
