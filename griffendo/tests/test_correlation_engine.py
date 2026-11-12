"""Correlation engine (v6): occurrence state, episode identity, deduplication, escalation.

These tests are written against the engine's own contract (no HTTP, no database) so a
failure points at the correlation logic rather than at the storage or the API.  The
end-to-end behaviour is covered by ``test_correlation_integration.py``.

Each test states the behaviour it protects, because the whole point of the v6 engine is
that its correlation rules are *stated* and *checkable* rather than implicit in a bucket.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path[:0] = [os.path.join(os.path.dirname(__file__), "..", "src")]

from logplatform.detection.correlation import identity, risk
from logplatform.detection.correlation.buckets import Bucketer
from logplatform.detection.correlation.config import CorrelationConfig
from logplatform.detection.correlation.state import ThresholdState


def cfg(**overrides) -> CorrelationConfig:
    base = {"bucket_minutes": 30, "default_timeout_seconds": 300, "max_signals_per_episode": 2000}
    base.update(overrides)
    return CorrelationConfig(**base)


# --------------------------------------------------------------------------- buckets
def test_bucket_index_is_pure_and_ordering_independent():
    """The same timestamp must always map to the same bucket, whatever order events arrive."""
    b = Bucketer(cfg(bucket_minutes=30))
    assert b.index(1_700_000_000.0) == b.index(1_700_000_000.0)
    assert b.index(1_700_000_000.0) == b.index(1_700_000_100.0)     # same 30-minute slice
    assert b.index(1_700_000_000.0) != b.index(1_700_002_000.0)
    assert b.start(b.index(1_700_000_000.0)) <= 1_700_000_000.0 < b.end(b.index(1_700_000_000.0))


def test_bucket_width_is_configurable():
    narrow, wide = Bucketer(cfg(bucket_minutes=5)), Bucketer(cfg(bucket_minutes=60))
    t = 1_700_001_000.0
    assert wide.index(t) <= narrow.index(t)


# --------------------------------------------------------------------------- identity
def test_entity_excludes_system_accounts_and_logon_sessions():
    """System accounts must not join unrelated activity (same rule as v5)."""
    event = {"user.name": "SYSTEM", "user.id": "S-1-5-18", "winlog.logon.id": "0x3e7"}
    assert identity.entity_key(event) is None or not identity.entity_key(event).startswith("logon:0x3e7")
    real = {"user.name": "alice", "user.id": "S-1-5-21-1-2-3-1001", "winlog.logon.id": "0x51ab"}
    assert identity.entity_key(real) == "logon:0x51ab"


def test_auth_correlation_key_separates_accounts_and_sources():
    """Brute force from one address is one incident; the same user locally is another."""
    base = {"user.name": "admin", "winlog.logon.id": "0x1", "event.code": "4625"}
    from_ip = {**base, "source.ip": "203.0.113.9"}
    local = {**base, "source.ip": "-"}
    entity = identity.entity_key(from_ip)
    a = identity.correlation_key(from_ip, entity, None)
    b = identity.correlation_key(local, entity, None)
    assert a != b
    assert "203.0.113.9" in a
    # Same account + same source -> the same incident, however many events arrive.
    assert a == identity.correlation_key(dict(from_ip), entity, None)


def test_process_correlation_key_scopes_to_the_process_tree():
    """Two unrelated command lines by one admin are different incidents (Dsiem backlog per chain)."""
    event = {"user.name": "alice", "event.code": "1", "process.entity_id": "{guid-2}"}
    entity = identity.entity_key(event)
    first = identity.correlation_key(event, entity, "{root-a}")
    second = identity.correlation_key(event, entity, "{root-b}")
    assert first != second
    assert first == identity.correlation_key(event, entity, "{root-a}")


# --------------------------------------------------------------------------- occurrence
def test_occurrence_requirement_withholds_until_met():
    """occurrence=5 must not alert on the first four matches."""
    state = ThresholdState()
    for i in range(4):
        obs = state.observe("R", "key", 1000.0 + i, required=5, timeout=300)
        assert not obs.reached, "must not fire before the requirement is met"
    obs = state.observe("R", "key", 1005.0, required=5, timeout=300)
    assert obs.reached and obs.first_fire
    assert obs.total == 5


def test_occurrence_beyond_requirement_is_a_separate_occurrence_not_a_second_alert_suppression():
    """Every match after the requirement is reported (so a burst keeps counting)."""
    state = ThresholdState()
    state.observe("R", "key", 1000.0, required=1, timeout=300)
    later = state.observe("R", "key", 1001.0, required=1, timeout=300)
    assert later.reached and not later.first_fire
    assert later.total == 2


def test_timeout_starts_a_new_series():
    """A match later than the rule's timeout is a new occurrence series, as Dsiem's backlog expiry."""
    state = ThresholdState()
    state.observe("R", "key", 1000.0, required=3, timeout=60)
    state.observe("R", "key", 1010.0, required=3, timeout=60)
    obs = state.observe("R", "key", 1200.0, required=3, timeout=60)   # > 60 s gap
    assert obs.new_series
    assert obs.total == 1, "the new series restarts the count"
    assert not obs.reached


def test_parallel_occurrences_do_not_compound_risk_but_are_counted():
    """A non-escalating rule reports 40 occurrences but keeps its risk at the required count."""
    state = ThresholdState()
    for i in range(40):
        obs = state.observe("R", "key", 1000.0 + i, required=1, timeout=300, escalate=False)
    assert obs.total == 40, "the analyst must see the real number of occurrences"
    assert obs.count == 1, "risk must not multiply with the occurrence count"


def test_escalating_occurrences_grow_the_risk_count():
    state = ThresholdState()
    for i in range(40):
        obs = state.observe("R", "key", 1000.0 + i, required=1, timeout=300, escalate=True)
    assert obs.count == 40


def test_state_is_bounded_and_purge_keeps_live_series():
    state = ThresholdState(max_keys=3)
    for i in range(10):
        state.observe("R", f"key{i}", 1000.0 + i, required=1, timeout=300)
    assert len(state.series) <= 3, "the in-memory state must stay bounded"
    state.observe("R", "live", 1000.0, required=1, timeout=300)
    state.purge(newest=1010.0, ttl=60)
    assert ("R", "live") in state.series


# --------------------------------------------------------------------------- escalation
def test_escalation_is_logarithmic_and_capped():
    small = risk.escalate(30.0, 10, enabled=True)
    large = risk.escalate(30.0, 1000, enabled=True)
    assert 0 < small["bonus"] < large["bonus"]
    assert large["bonus"] <= CorrelationConfig().occurrence_escalation_max + 1e-9
    assert risk.escalate(30.0, 1, enabled=True)["bonus"] == 0, "a single occurrence never escalates"


def test_escalation_is_opt_in_per_rule():
    """A rule that does not escalate must not grow with repetition."""
    assert risk.escalate(30.0, 500, enabled=False)["bonus"] == 0


def test_combine_keeps_strongest_signal_and_explains_escalation():
    signals = [{"id": "a", "rule_id": "R1", "score": 30.0, "last_time": "2026-01-01T00:00:00Z", "event_keys": ["e1"],
                "source": "rule", "confidence": "high"},
               {"id": "b", "rule_id": "R1", "score": 30.0, "last_time": "2026-01-01T00:00:01Z", "event_keys": ["e2"],
                "source": "rule", "confidence": "high"}]
    combined = risk.combine(signals, occurrences={"R1": 40}, escalate_rules={"R1"})
    assert combined["score"] > combined["base_score"]
    assert combined["escalation"]["applied"] > 0
    assert combined["occurrences"]["R1"] == 40
    text = risk.explain(combined, {})
    assert "Repetition adds" in text


def test_two_rules_correlate_into_a_higher_score_than_either_alone():
    """Corroboration, not volume, is what raises an episode above one rule's score."""
    one = [{"id": "a", "rule_id": "R1", "score": 50.0, "last_time": "2026-01-01T00:00:00Z", "event_keys": ["e1"],
            "source": "rule", "confidence": "high"}]
    two = one + [{"id": "b", "rule_id": "R2", "score": 50.0, "last_time": "2026-01-01T00:00:00Z", "event_keys": ["e2"],
                  "source": "rule", "confidence": "high"}]
    assert risk.combine(two)["score"] > risk.combine(one)["score"]


def test_same_event_matched_by_two_rules_is_corroboration_not_double_evidence():
    shared = [{"id": "a", "rule_id": "R1", "score": 50.0, "last_time": "2026-01-01T00:00:00Z", "event_keys": ["e1"],
               "source": "rule", "confidence": "high"},
              {"id": "b", "rule_id": "R2", "score": 50.0, "last_time": "2026-01-01T00:00:00Z", "event_keys": ["e1"],
               "source": "rule", "confidence": "high"}]
    combined = risk.combine(shared)
    assert combined["corroborating"] == ["b"]
    assert combined["score"] == 50.0, "the same event must not be counted twice"


@pytest.mark.parametrize("value,expected", [(1, 0.0), (10, 4.0), (100, 8.0)])
def test_escalation_curve_matches_documentation(value, expected):
    bonus = risk.escalate(0.0, value, enabled=True)["bonus"]
    assert abs(bonus - min(expected, CorrelationConfig().occurrence_escalation_max)) < 0.01


# --------------------------------------------------------------------------- DSIEM stages
def _stages(*rows):
    return [{"occurrence": o, "timeout_seconds": t, "reliability": r} for o, t, r in rows]


def test_stage_block_is_validated_with_actionable_errors():
    """A rule's stages are authored by users, so a bad block must be rejected with a reason."""
    from logplatform.detection.correlation import stages as stage_model
    assert stage_model.parse({}) == []
    parsed = stage_model.parse({"stages": _stages((1, 300, 1), (3, 3600, 6), (100, 7200, 10))})
    assert [s.index for s in parsed] == [1, 2, 3]
    with pytest.raises(ValueError, match="stage 1: occurrence must be 1"):
        stage_model.parse({"stages": _stages((2, 300, 1))})
    with pytest.raises(ValueError, match="must not decrease"):
        stage_model.parse({"stages": _stages((1, 300, 1), (5, 300, 2), (4, 300, 3))})
    with pytest.raises(ValueError, match="reliability must be 1-10"):
        stage_model.parse({"stages": _stages((1, 300, 11))})


def test_stage_escalates_with_occurrences_and_maps_reliability_to_score():
    """The DSIEM contract: more occurrences -> later stage -> higher reliability -> higher score."""
    from logplatform.detection.correlation import stages as stage_model
    parsed = stage_model.parse({"stages": _stages((1, 600, 1), (3, 3600, 6), (10, 7200, 10))})
    one = stage_model.evaluate(parsed, 1, 0)
    three = stage_model.evaluate(parsed, 3, 0)
    ten = stage_model.evaluate(parsed, 10, 0)
    assert (one["stage"], one["score"]) == (1, 10)
    assert (three["stage"], three["score"]) == (2, 60)
    assert (ten["stage"], ten["score"]) == (3, 100)
    assert one["next_occurrence"] == 3 and ten["next_occurrence"] is None


def test_stage_expires_when_its_timeout_passes_without_escalating():
    from logplatform.detection.correlation import stages as stage_model
    parsed = stage_model.parse({"stages": _stages((1, 600, 1), (5, 3600, 8))})
    assert stage_model.evaluate(parsed, 2, 900)["expired"] is True
    assert stage_model.evaluate(parsed, 2, 100)["expired"] is False
    # Reaching the next stage resets the waiting clock: the stage is no longer expired.
    assert stage_model.evaluate(parsed, 5, 900)["expired"] is False


def test_staged_rule_score_is_replaced_by_the_stage_before_the_noisy_or():
    """A stage score must drive the episode score, not merely decorate the explanation."""
    from logplatform.detection.correlation import stages as stage_model
    parsed = stage_model.parse({"stages": _stages((1, 600, 1), (3, 3600, 9))})
    signal = {"id": "a", "rule_id": "R1", "score": 10.0, "last_time": "2026-01-01T00:00:00Z",
              "event_keys": ["e1"], "source": "rule", "confidence": "high"}
    low = risk.combine([signal], occurrences={"R1": 1}, stages_by_rule={"R1": parsed})
    high = risk.combine([signal], occurrences={"R1": 3}, stages_by_rule={"R1": parsed})
    assert low["score"] == 10.0 and low["stages"]["R1"]["stage"] == 1
    assert high["score"] == 90.0 and high["stages"]["R1"]["stage"] == 2
    assert high["contributors"][0]["base_rule_score"] == 10.0
    assert "stage score 90" in risk.explain(high, {})
    # A rule without stages behaves exactly as before.
    assert "stages" in risk.combine([signal], occurrences={"R1": 3})
