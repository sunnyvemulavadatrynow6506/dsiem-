"""Occurrence state machine: DSIEM's ``occurrence`` + ``timeout``, rebuilt for event streams.

DSIEM gives every directive rule an ``occurrence`` count and a ``timeout``.  A backlog
accumulates matching events; when the stage reaches ``occurrence`` the rule is "finished"
and the alarm is updated; if nothing arrives within ``timeout`` the backlog expires.  That
gives SIEMs three behaviours from one primitive: fire once, fire on the Nth event, and
start a fresh series after a quiet period.

v5 had no such state across events: a threshold rule (*EQL* style) counted inside a
sliding window and then *consumed* the events, so after the first alert it went quiet,
and a plain rule alerted on every single event with no notion of a series.

:class:`ThresholdState` implements:

``observe(rule_id, key, t, required, timeout, escalate, event)`` → :class:`Observation`
    * ``required`` N  — the rule fires when the series reaches N matching events;
    * ``timeout``     — a match arriving later than ``timeout`` after the previous one
                        starts a *new* series (count restarts at 1);
    * ``escalate``    — when true, later matches of the same series keep counting (bounded),
                        so the episode can escalate; when false the series is capped at
                        ``required`` and every further match is an independent occurrence
                        (parallel, not serial), which is what makes N failed logons one
                        incident rather than N incidents.

The state is in memory, bounded (LRU + per-key cap) and rebuilt identically by the
start-up replay, so it needs no persistence of its own.  Evidence events of pending
matches are retained in the series (bounded) so that a signal which fires carries the
events that caused it, and nothing is invented when it does not fire.
"""
from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

MAX_EVIDENCE = 25


def _env_int(name: str, default: int, low: int) -> int:
    try:
        return max(low, int(float(os.getenv(name, str(default)))))
    except (TypeError, ValueError):
        return default


@dataclass
class Series:
    """One occurrence series: consecutive matches of one rule for one correlation key.

    ``count`` is the *true* number of matches in the series and is what the UI and the
    analyst see.  ``effective`` is what the risk model may use: for a non-escalating rule
    it stays at the required count, so repetition is reported but never compounds into
    score; for an escalating rule it grows, and the escalation curve is bounded anyway.
    """

    rule_id: str
    key: str
    count: int = 0
    first_time: float = 0.0
    last_time: float = 0.0
    fired: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)

    def add(self, t: float, event: dict[str, Any] | None) -> None:
        if self.count == 0:
            self.first_time = t
        self.count += 1
        self.last_time = max(self.last_time, t)
        if event is not None and len(self.events) < MAX_EVIDENCE:
            self.events.append(event)
        elif event is not None and self.events:
            # Keep the most recent evidence when the series is very long: the newest events
            # describe the current state of the attack, the oldest the beginning.
            self.events[-1] = event

    def age(self, t: float) -> float:
        return t - self.last_time


@dataclass
class Observation:
    """What :meth:`ThresholdState.observe` decided for one match."""

    reached: bool                  # the series now holds at least the required occurrences
    first_fire: bool               # this match is the one that first satisfied the requirement
    count: int                     # occurrences the risk model may use (capped when not escalating)
    total: int                     # true occurrences in the series (what the analyst sees)
    first_time: float              # start of the series (its identity for counting)
    last_time: float
    new_series: bool
    events: list[dict[str, Any]]
    required: int
    timeout: float


class ThresholdState:
    """Bounded per-(rule, correlation key) occurrence state."""

    def __init__(self, max_keys: int | None = None, max_per_key: int = 10000) -> None:
        self.max_keys = max_keys or _env_int("GRIFFENDO_CORRELATION_MAX_SERIES", 100000, 1000)
        self.max_per_key = max_per_key
        self.series: OrderedDict[tuple[str, str], Series] = OrderedDict()
        self.started = 0
        self.expired = 0

    # ------------------------------------------------------------------ observe
    def observe(self, rule_id: str, key: str, t: float, required: int = 1,
                timeout: float = 300.0, escalate: bool = False,
                event: dict[str, Any] | None = None) -> Observation:
        required = max(1, int(required))
        slot = (rule_id, key)
        series = self.series.get(slot)
        new_series = False
        if series is None:
            series = Series(rule_id=rule_id, key=key)
            self.series[slot] = series
            new_series = True
            self._evict()
        elif series.count and timeout > 0 and series.age(t) > timeout:
            # A quiet gap longer than the rule's timeout: a new occurrence series begins.
            series = Series(rule_id=rule_id, key=key)
            self.series[slot] = series
            new_series = True
            self.expired += 1
        self.series.move_to_end(slot)
        series.add(t, event)
        # A non-escalating rule keeps its risk at the required count ("N events happened",
        # not "N times as bad"); an escalating rule grows so the escalation curve sees it.
        effective = series.count if escalate else min(series.count, required)
        reached = effective >= required
        first_fire = reached and not series.fired
        if reached:
            series.fired = True
        if first_fire:
            self.started += 1
        return Observation(reached=reached, first_fire=first_fire, count=effective,
                           total=series.count, first_time=series.first_time, last_time=series.last_time,
                           new_series=new_series, events=list(series.events),
                           required=required, timeout=timeout)

    # ------------------------------------------------------------------ housekeeping
    def _evict(self) -> None:
        while len(self.series) > self.max_keys:
            self.series.popitem(last=False)

    def purge(self, newest: float, ttl: float) -> int:
        """Drop series that can no longer contribute (older than ``ttl`` before ``newest``)."""
        cutoff = newest - ttl
        stale = [slot for slot, series in self.series.items() if series.last_time < cutoff]
        for slot in stale:
            del self.series[slot]
        return len(stale)

    def reset(self) -> None:
        self.series.clear()

    def stats(self) -> dict[str, int]:
        return {"series": len(self.series), "fired_series": self.started, "expired_series": self.expired}
