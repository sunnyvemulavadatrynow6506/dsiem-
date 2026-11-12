"""Correlation engine: turn per-event rule matches ("signals") into episodes ("detections").

Pipeline (each step is a small function so it can be tested and replaced alone):

    1. classify      a raw rule match -> SignalFacts (identity + occurrence + expiry)
    2. occurrence    ThresholdState decides whether the rule has fired yet
    3. emit          a fired match becomes an EpisodeDraft candidate (evidence attached)
    4. place         the draft is attached to an open episode of the same correlation key,
                     or a new episode is opened in its time bucket
    5. score         v5 noisy-OR over distinct rules + bounded occurrence escalation
    6. summarise     title, category, MITRE, confidence and analyst-facing explanation

What changed against v5, in one sentence: v5 grouped signals into a fixed 30-minute
(entity, bucket) cold, so every matching event produced its own detection and repetition
was invisible; v6 keeps an **open episode per correlation key**, lets later evidence join it
while it is still live, fires a rule only when its ``occurrence`` requirement is met, and
escalates risk for repetition — the three things DSIEM's backlog model gets right.

The engine is pure: it never touches the database.  ``service.py`` stores what it returns,
which keeps the correlation logic testable without I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import buckets, config, identity, risk
from .config import CorrelationConfig
from .state import Observation, ThresholdState


@dataclass
class SignalFacts:
    """A rule match, annotated with what the correlator needs to place it."""

    signal: dict[str, Any]            # the v5-style signal dict (rule, events, score, ...)
    rule_id: str
    entity_key: str | None
    correlation_key: str
    bucket: int
    first_time: float
    last_time: float
    required: int = 1
    timeout: float = 300.0
    escalate: bool = False
    correlation: dict[str, Any] = field(default_factory=dict)


@dataclass
class EpisodeDraft:
    """An episode (detection) built from one or more fired signals."""

    id: str
    correlation_key: str
    entity_key: str | None
    bucket: int
    signals: list[dict[str, Any]]
    first_time: float
    last_time: float
    occurrences: dict[str, int]
    combined: dict[str, Any]
    reason: str = ""

    @property
    def score(self) -> float:
        return float(self.combined["score"])

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "correlation_key": self.correlation_key, "entity_key": self.entity_key,
                "bucket": self.bucket, "score": self.score, "severity": self.combined["severity"],
                "first_time": self.first_time, "last_time": self.last_time,
                "signals": [s.get("id") for s in self.signals], "occurrences": self.occurrences}


class CorrelationEngine:
    """Stateful correlator: one instance per detection service."""

    def __init__(self, cfg: CorrelationConfig | None = None, state: ThresholdState | None = None) -> None:
        self.cfg = cfg or config.current()
        self.bucketer = buckets.Bucketer(self.cfg)
        self.state = state or ThresholdState()
        self._cursors: dict[str, dict[str, Any]] = {}
        self.newest = 0.0

    # ------------------------------------------------------------------ 1. classify
    def classify(self, signal: dict[str, Any], rule, t: float, ancestors: list[str] | None = None,
                 process_key: str | None = None) -> SignalFacts:
        """Annotate a raw rule match with identity, occurrence policy and expiry.

        The occurrence policy comes from the rule's ``correlation`` block, falling back to
        the kind of the rule so that imported Elastic/Wazuh rules keep their meaning:

            threshold rule        fires on its own (the matcher already counted), so the
                                  occurrence requirement is 1 and the window is honoured
            everything else        occurrence defaults to 1, timeout to the configured default
        """
        events = signal.get("events") or []
        # The event that triggered the match is the last one appended by the matcher; its
        # content decides identity (an earlier event of a sequence may belong to another actor).
        anchor = events[-1] if events else {}
        entity = identity.entity_key(anchor)
        root = identity.process_root(anchor, ancestors) if process_key else identity.process_root(anchor, None)
        corr = identity.correlation_key(anchor, entity, root)
        block = dict(getattr(rule, "spec", {}).get("correlation") or {})
        kind = getattr(rule, "kind", "single")
        if kind == "threshold":
            required = 1
            timeout = float((rule.spec.get("threshold") or {}).get("window_seconds")
                            or self.cfg.default_timeout_seconds)
        else:
            required = max(1, int(block.get("occurrence", 1) or 1))
            timeout = float(block.get("timeout_seconds") or self.cfg.default_timeout_seconds)
        return SignalFacts(signal=signal, rule_id=rule.id, entity_key=entity, correlation_key=corr,
                           bucket=self.bucketer.index(t), first_time=t, last_time=t,
                           required=required, timeout=timeout,
                           escalate=bool(block.get("escalate")), correlation=block)

    # ------------------------------------------------------------------ 2-3. occurrence
    def observe(self, facts: SignalFacts, event: dict[str, Any] | None = None) -> Observation:
        return self.state.observe(facts.rule_id, facts.correlation_key, facts.last_time,
                                  required=facts.required, timeout=facts.timeout,
                                  escalate=facts.escalate, event=event)

    # ------------------------------------------------------------------ 4. place
    def place(self, facts: SignalFacts, t: float) -> tuple[str, int]:
        """Which open episode should receive this signal, and in which bucket.

        Continuity rule (tested): evidence joins the open episode of the same correlation
        key even when it crosses a bucket boundary, as long as the gap is within the rule's
        timeout.  Otherwise a fresh episode opens in the event's own bucket.
        """
        known = self._cursors.get(facts.correlation_key)
        if known and self.cfg.bucket_minutes > 0:
            gap = t - known["last_time"]
            # Stay in the open episode while the series is unbroken (no gap beyond the rule's
            # timeout).  The episode keeps the bucket it opened in, so a multi-hour brute-force
            # run remains one incident instead of splitting at every bucket boundary.
            if 0 <= gap <= max(facts.timeout, self.bucketer.width):
                return known["episode"], known["bucket"]
        bucket = self.bucketer.index(t)
        episode = _episode_id(facts.correlation_key, bucket)
        return episode, bucket

    def remember(self, facts: SignalFacts, episode: str, bucket: int, t: float) -> None:
        current = self._cursors.get(facts.correlation_key)
        if current is None or current["episode"] != episode or t >= current["last_time"]:
            self._cursors[facts.correlation_key] = {"episode": episode, "bucket": bucket, "last_time": t}
        self.newest = max(self.newest, t)
        if len(self._cursors) > 200000:
            oldest = min(self._cursors.items(), key=lambda item: item[1]["last_time"])[0]
            self._cursors.pop(oldest, None)

    def reopen(self, facts: SignalFacts, episode: str, bucket: int, last_time: float) -> None:
        """Restore continuity after a restart (the service replays the stored cursors)."""
        self._cursors[facts.correlation_key] = {"episode": episode, "bucket": bucket, "last_time": last_time}
        self.newest = max(self.newest, last_time)

    # ------------------------------------------------------------------ 5-6. score
    def build(self, episode_id: str, correlation_key: str, entity_key: str | None, bucket: int,
              signals: list[dict[str, Any]], occurrences: dict[str, int], escalate_rules: set[str],
              rules: dict[str, Any]) -> EpisodeDraft:
        combined = risk.combine(signals, occurrences, escalate_rules, self.cfg)
        combined["reason"] = risk.explain(combined, rules)
        first = min(s["first_time"] for s in signals)
        last = max(s["last_time"] for s in signals)
        return EpisodeDraft(id=episode_id, correlation_key=correlation_key, entity_key=entity_key, bucket=bucket,
                            signals=signals, first_time=first, last_time=last, occurrences=occurrences,
                            combined=combined, reason=combined["reason"])

    # ------------------------------------------------------------------ housekeeping
    def purge(self) -> dict[str, int]:
        if not self.newest:
            return {"series": 0, "cursors": 0}
        ttl = max(self.bucketer.width * 6, 6 * 3600)
        expired = self.state.purge(self.newest, ttl)
        cutoff = self.newest - ttl
        stale = [key for key, item in self._cursors.items() if item["last_time"] < cutoff]
        for key in stale:
            del self._cursors[key]
        return {"series": expired, "cursors": len(stale)}

    def stats(self) -> dict[str, Any]:
        return {**self.state.stats(), "open_cursors": len(self._cursors),
                "bucket_minutes": self.cfg.bucket_minutes,
                "config": self.cfg.public()}


def _episode_id(correlation_key: str, bucket: int) -> str:
    """Stable episode id: identical for replay, re-evaluation and live processing."""
    import hashlib
    return hashlib.sha256(f"{correlation_key}|{bucket}".encode("utf-8")).hexdigest()[:32]
