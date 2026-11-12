"""Correlation engine (v6): stateful episode correlation for Griffendo.

This package replaces the v5 "signal -> fixed 30-minute bucket" grouping, which
raised one detection per matching event and therefore could not express
repetition, escalation or incident continuity (measured on the v5.1 synthetic
corpus: 279 detections from 347 signals, 112 of them a single failed logon).

The design follows DSIEM's proven directives in deliberate ways:

    DSIEM concept                        v6 equivalent
    -----------------------------------  ---------------------------------------------------
    directive backlog tied to an entity  Episode: one (entity, time bucket) correlation context
    rule stage + ``occurrence``          a signal's ``occurrence``/``threshold`` must be met
                                         before the rule fires (threshold state machine)
    ``timeout`` per rule                 ``timeout_seconds`` on the threshold state: a new
                                         match after the timeout starts a new occurrence series
    several rules fill one backlog       several rules matching the same entity/bucket join one
                                         episode (deduplication)
    backlog ``risk`` escalation          episode risk = noisy-OR over distinct rules plus a
                                         bounded, documented occurrence escalation
    alarm de-duplication by backlog id    episode id is a pure function of (entity, bucket), so
                                         replay and re-evaluation are idempotent

Stages (each a separate module, so a new capability does not touch the others):

    identity.py  what "the same thing" means (entity + correlation key)
    buckets.py   fixed, configurable time buckets (ordering-independent)
    state.py     threshold/occurrence state machine (pending buckets, series continuity)
    engine.py    the pipeline: signals -> classified -> correlated -> episodes -> events
    risk.py      v5 scorer, reused unchanged; escalation lives here

The engine never discards evidence: every match is stored as a signal row with
the events that produced it, and an episode references the signals (and so the
events) that built it.
"""
from .engine import CorrelationEngine, EpisodeDraft, SignalFacts
from .identity import entity_key, correlation_key
from .buckets import Bucketer
from .state import ThresholdState

__all__ = ["CorrelationEngine", "EpisodeDraft", "SignalFacts", "entity_key", "correlation_key",
           "Bucketer", "ThresholdState"]
