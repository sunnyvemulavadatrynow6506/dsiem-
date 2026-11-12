"""Correlation settings: every tunable in one place, all overridable by environment.

Defaults were chosen from the measured v5.1 corpus (7 days, ~6k events, 345 rules)
and are documented in docs/CORRELATION_ENGINE.md.  Reading them through this module
(rather than calling os.getenv in the engine) keeps the pipeline testable and makes
the effective configuration visible on the Settings page and in /api/detections/status.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(float(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


@dataclass(frozen=True)
class CorrelationConfig:
    # Fixed episode buckets, in event time.  A bucket never depends on arrival order, so a
    # historical replay produces exactly the same episodes as live processing.
    bucket_minutes: int = 30
    # A rule's threshold state expires when a match arrives this long after the previous one.
    # 0 means "use the rule's own timeout_seconds, else this default".
    default_timeout_seconds: int = 300
    # Safety valve: an episode is closed for writes after this many signals (evidence is kept).
    max_signals_per_episode: int = 2000
    # Occurrence escalation: a bounded bonus for repeated occurrences of the same rule, so a
    # brute-force burst outranks a single event without compounding with itself.
    occurrence_escalation: bool = True
    occurrence_escalation_max: float = 12.0
    # Only rules whose correlation block sets "escalate": true may escalate.
    escalation_per_decade: float = 4.0
    # Confidence of a multi-rule episode: an episode supported by two independent rules is at
    # least this confident.
    corroboration_confidence: str = "medium"
    # Suppression: a signal is suppressed only on the same rule AND the same fingerprint.
    suppression_enabled: bool = True

    @classmethod
    def from_env(cls) -> "CorrelationConfig":
        return cls(
            bucket_minutes=_int("GRIFFENDO_CORRELATION_BUCKET_MINUTES", 30, 1, 1440),
            default_timeout_seconds=_int("GRIFFENDO_CORRELATION_TIMEOUT_SECONDS", 300, 1, 86400),
            max_signals_per_episode=_int("GRIFFENDO_CORRELATION_MAX_SIGNALS", 2000, 10, 100000),
            occurrence_escalation=os.getenv("GRIFFENDO_RISK_OCCURRENCE_ESCALATION", "1") != "0",
            occurrence_escalation_max=_float("GRIFFENDO_RISK_OCCURRENCE_MAX", 12.0, 0.0, 40.0),
            escalation_per_decade=_float("GRIFFENDO_RISK_ESCALATION_PER_DECADE", 4.0, 0.0, 20.0),
            suppression_enabled=os.getenv("GRIFFENDO_SUPPRESSION", "1") != "0",
        )

    def public(self) -> dict[str, object]:
        return {
            "bucket_minutes": self.bucket_minutes,
            "default_timeout_seconds": self.default_timeout_seconds,
            "max_signals_per_episode": self.max_signals_per_episode,
            "occurrence_escalation": self.occurrence_escalation,
            "occurrence_escalation_max": self.occurrence_escalation_max,
            "escalation_per_decade": self.escalation_per_decade,
            "corroboration_confidence": self.corroboration_confidence,
            "suppression_enabled": self.suppression_enabled,
        }


CURRENT = CorrelationConfig.from_env()


def current() -> CorrelationConfig:
    """Effective configuration (re-read on demand so tests and the UI can change it)."""
    return CURRENT
