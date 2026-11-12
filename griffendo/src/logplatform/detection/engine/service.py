"""Detection service: runs the pipeline in the background and owns rule switching, re-evaluation and feedback.

Processing is separate from collection: ingest stores events and wakes the worker; the
worker reads new events after its checkpoint (events.rowid) in batches, evaluates them
and stores signals/detections, then advances the checkpoint in the same transaction.
After a restart it first replays the most recent correlation window of stored events
to rebuild in-memory state (signals are not re-stored), then continues from the
checkpoint, so nothing is processed twice and nothing is skipped.
"""
from __future__ import annotations

import json
import threading
import time
import traceback
from datetime import timedelta
from typing import Any, Iterable

from ... import busy, db, settings
from ...settings import env_int, iso, parse_time, utc_now
from ...state import StateStore
from . import aggregator as agg
from . import behavior as beh
from . import decision as dec
from . import feedback as fb
from . import model_store, normalizer, registry as reg, risk, store
from ..correlation import aggregator as correlation_agg
from ..correlation.engine import CorrelationEngine
from ..correlation.identity import entity_key as correlation_entity
from .chain import ChainCorrelator
from .matcher import Matcher, WazuhTree, draft
from .state import StateManager, epoch

EVENT_COLUMNS = ("rowid AS _rowid, id, hostname, channel, record_id, event_time, normalized_json, provider, event_id, "
                 "collected_at, CASE WHEN instr(normalized_json, '\"system\":') = 0 THEN raw_xml END AS raw_fallback")
PROCESS_EVENTS = ("(channel = 'Security' AND event_id IN (4688, 4689, 4624, 4672, 4634, 4647)) OR "
                  "(channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id IN (1, 5))")
FLAGGING = {"Critical", "High", "Medium"}


def window_days() -> int:
    return env_int("GRIFFENDO_DETECTION_WINDOW_DAYS", 7, 1)


def batch_size() -> int:
    return env_int("GRIFFENDO_DETECTION_BATCH", 2000, 50)


class DetectionService:
    def __init__(self, rules: list | None = None, rule_errors: list[str] | None = None, start_worker: bool = True):
        self.lock = threading.RLock()            # engine state (one batch at a time)
        self.state_store = StateStore(settings.state_dir() if settings.storage_mode() == "disk" else None)
        self.models = model_store.ModelStore(settings.state_dir() if settings.storage_mode() == "disk" else None)
        store.initialize()
        if rules is None:
            from ..rules import load_all
            rules, rule_errors = load_all()
        self.registry = reg.Registry(rules, rule_errors)
        self._load_custom_rules()
        self._apply_overrides()
        self.state = StateManager()
        self._coverage_cache: tuple[float, float | None] = (0.0, None)
        self.terms = model_store.TermStore(self.models, self._covered)
        self.matcher = Matcher(self.state, self.terms)
        self.chains = ChainCorrelator(self.state)
        self.tree = WazuhTree(self.registry.wazuh, self.state, self.terms)
        self.behavior = beh.BehaviorModel(self.models.get("behavior"))
        self.decider = dec.Decider(self.state_store.suppressions())
        self.correlator = CorrelationEngine()
        self.aggregator = correlation_agg.EpisodeAggregator(lambda: self.registry, self.correlator)
        self.stats = {"processed": 0, "signals": 0, "batches": 0, "errors": 0, "last_error": None,
                      "last_batch_at": None, "last_batch_ms": None, "events_per_second": None, "replayed": 0,
                      "started_at": iso(utc_now())}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.jobs_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._last_model_save = time.monotonic()
        self._thread = None
        self.replaying = False
        if not start_worker:
            self.replay()            # tests and tools: synchronous
        else:
            self.replaying = True    # the worker replays first, off the start-up path
            self._thread = threading.Thread(target=self._run, name="griffendo-detection", daemon=True)
            self._thread.start()

    # ------------------------------------------------------------------ rules
    def _load_custom_rules(self) -> None:
        for definition in self.state_store.custom_rules(include_deleted=True):
            spec = custom_spec(definition)
            try:
                rule = reg.Rule(spec, module="custom")
            except reg.RuleError as error:
                self.registry.errors.append(str(error))
                continue
            if definition.get("deleted_at"):
                self.registry.retired[rule.id] = {**rule.public(), "deleted_at": definition["deleted_at"]}
                continue
            rule.enabled = bool(definition.get("enabled"))
            self.registry.rules[rule.id] = rule
        self.registry.rebuild()

    def _apply_overrides(self) -> None:
        for rule_id, override in self.state_store.overrides().items():
            rule = self.registry.get(rule_id)
            if rule and rule.origin != "custom" and not rule.protected:
                rule.enabled = bool(override["enabled"])
        self.registry.rebuild()

    def _covered(self, since: float) -> bool:
        checked, earliest = self._coverage_cache
        if time.monotonic() - checked > 60 or earliest is None:
            with db.connect() as connection:
                row = connection.execute("SELECT MIN(event_time) FROM events").fetchone()
            parsed = parse_time(row[0]) if row and row[0] else None
            earliest = parsed.timestamp() if parsed else None
            self._coverage_cache = (time.monotonic(), earliest)
        return earliest is not None and earliest <= since + 60

    # ------------------------------------------------------------------ pipeline
    def evaluate_event(self, ev: dict[str, Any], t: float, rules: Iterable | None = None,
                       use_behavior: bool = True, use_wazuh: bool = True) -> list[dict[str, Any]]:
        process_key = self.state.observe(ev, t)
        signals: list[dict[str, Any]] = []
        candidates = rules if rules is not None else self.registry.candidates(ev.get("winlog.channel"),
                                                                              ev.get("winlog.event_id"))
        for rule in candidates:
            if not rule.enabled:
                continue
            try:
                if rule.kind == "chain":
                    signals += self.chains.evaluate(rule, ev, t, process_key)
                elif rule.kind in ("single", "threshold", "sequence", "new_terms"):
                    signals += self.matcher.evaluate(rule, ev, t)
            except Exception as error:   # one faulty rule must not stop the others
                self.stats["errors"] += 1
                self.stats["last_error"] = f"{rule.id}: {error}"
        if use_wazuh and self.tree.roots:
            try:
                signals += self.tree.evaluate(ev, t)
            except Exception as error:
                self.stats["errors"] += 1
                self.stats["last_error"] = f"wazuh tree: {error}"
        if use_behavior:
            signals += self._behavior(ev, t, signals)
        return signals

    def _behavior(self, ev: dict[str, Any], t: float, rule_signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        model = self.behavior
        out: list[dict[str, Any]] = []
        stage = model.state["stage"]
        for finding in model.rate_events(ev, t):
            rule = self.registry.get("BEH-VOLUME")
            if stage != "learn" and rule and rule.enabled and finding["score"] >= model.threshold():
                reference = {"_key": f"rate:{finding['feature']}:{finding['bucket_start']}",
                             "@timestamp": finding["bucket_start"], "host.name": ev.get("host.name"),
                             "_raw": {}, "_lower": {}, "griffendo.rate": finding}
                # A behaviour signal stays inside its rule's configured severity band; only corroboration by
                # other signals (aggregator) can raise a detection above it.
                signal = draft(rule, [reference], source="behavior",
                               score=risk.rule_score(rule.severity, round(finding["score"] * 100)),
                               details={"behavior": {"rate": finding, "stage": stage}})
                signal["severity"] = risk.severity_for(signal["score"])
                out.append(signal)
                if stage == "shadow":
                    model.state["shadow"]["would_alert"] += 1
        features = model.features(ev)
        if not any(features.values()):
            return out
        logon = self.state.logons.get(ev.get("winlog.logon.id"))
        result = model.score(ev, features, privileged=bool(logon and logon.get("privileged")))
        result["rule_flagged"] = any(s["severity"] in FLAGGING for s in rule_signals)
        if stage == "shadow":
            model.state["shadow"]["observations"] += 1
        if stage != "learn" and result["R"] >= model.threshold() and result["parts"]:
            top = max(result["parts"], key=lambda p: p["weight"] * p["score"])
            family = beh.FAMILY.get(top["feature"], "process")
            rule = self.registry.get(beh.RULE_FOR_FAMILY[family])
            if rule and rule.enabled:
                signal = draft(rule, [ev], source="behavior", score=risk.rule_score(rule.severity, round(result["R"] * 100)),
                               details={"behavior": {**result, "stage": stage, "threshold": model.threshold()}})
                signal["severity"] = risk.severity_for(signal["score"])
                signal["confidence"] = "medium" if result["R"] < 0.8 else "high"
                out.append(signal)
                if stage == "shadow":
                    model.state["shadow"]["would_alert"] += 1
        model.learn(features, t, result)
        if model.state["observations"] % 500 == 0:
            change = model.lifecycle(t)
            if change:
                self.models.audit("lifecycle", change)
        return out

    # ------------------------------------------------------------------ correlation
    def correlate(self, signals: list[dict[str, Any]], ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        """Attach every rule match to its episode and apply the rule's occurrence requirement.

        This is the bridge between the v5 rule matchers (unchanged) and the v6 correlator:

          * behaviour-model signals are already aggregated by the model and are passed
            through untouched (they have no occurrence semantics);
          * each deterministic match is classified (identity, occurrence policy, expiry) and
            observed by the threshold state machine;
          * only a match that *fires* (its occurrence requirement is met) becomes a new
            detection contributor.  A non-firing match is still counted, and once the series
            fires it contributes its accumulated occurrences, so a threshold of N is reported
            as one detection with N occurrences instead of N detections;
          * the episode that receives the match is remembered for continuity.
        """
        if not signals:
            return signals
        out: list[dict[str, Any]] = []
        ancestors = self.state.processes.ancestors(self.state.processes.resolve(
            ev.get("process.entity_id"), ev.get("process.pid"), t)) if ev.get("process.entity_id") else None
        for signal in signals:
            if signal.get("source") == "behavior":
                out.append(signal)
                continue
            rule = signal.get("rule")
            if rule is None:
                out.append(signal)
                continue
            facts = self.correlator.classify(signal, rule, t, ancestors=ancestors,
                                            process_key=ev.get("process.entity_id"))
            episode, bucket = self.correlator.place(facts, t)
            observation = self.correlator.observe(facts, ev)
            signal["episode_id"] = episode
            details = signal.setdefault("details", {})
            details["episode_bucket"] = bucket
            details["correlation"] = {"key": facts.correlation_key, "occurrence_required": facts.required,
                                      "occurrence_count": observation.total,
                                      "occurrences": observation.total,
                                      "timeout_seconds": int(facts.timeout),
                                      "escalate": facts.escalate,
                                      "series_started": observation.new_series}
            details["occurrences"] = observation.total
            self.correlator.remember(facts, episode, bucket, t)
            if not observation.reached:
                # Occurrence requirement not met yet.  The match is counted by the threshold
                # state and is reported by the signal that satisfies the requirement, so a
                # rule with occurrence=5 produces one detection carrying five events.
                continue
            details["occurrences"] = observation.total
            details["risk_occurrences"] = observation.count
            # Every occurrence at or above the requirement contributes to the same episode, so
            # a brute-force burst grows one detection (occurrence_count + escalation) instead of
            # silently stopping after the first match.
            signal["details"]["occurrence_series"] = {"first_time": observation.first_time,
                                                      "count": observation.total,
                                                      "risk_count": observation.count,
                                                      "required": observation.required,
                                                      "first_fire": observation.first_fire}
            if not observation.first_fire:
                # Subsequent occurrences of the same series are corroboration, not new findings:
                # they are stored so the episode counts them, but they must not re-raise the score
                # from scratch (the aggregator caps one rule at its own score).
                signal["_repeat"] = True
            if len(observation.events) > 1:
                signal["events"] = (observation.events + signal["events"])[-25:]
                signal["event_keys"] = [item["_key"] for item in signal["events"]]
            out.append(signal)
        return out

    def process_rows(self, rows: list, origin: str = "live", persist: bool = True,
                     use_behavior: bool = True) -> dict[str, int]:
        events = []
        for row in rows:
            ev = normalizer.normalize(row)
            events.append((epoch(ev["@timestamp"]), ev))
        events.sort(key=lambda item: item[0])
        stage = self.behavior.state["stage"]
        produced = []
        for t, ev in events:
            signals = self.evaluate_event(ev, t, use_behavior=use_behavior)
            signals = self.correlate(signals, ev, t)
            for signal in signals:
                self.decider.decide(signal, stage)
            if signals:
                produced.append((ev, signals))
        counts = {"events": len(events), "signals": sum(len(s) for _, s in produced), "detections": 0}
        if not persist:
            for _, signals in produced:
                for signal in signals:
                    self.state.mark_used(signal["rule_id"], signal["event_keys"])
            return counts
        touched: set[str] = set()
        with db.connect() as connection:
            for ev, signals in produced:
                rates = [s for s in signals if s["event_keys"][0].startswith("rate:")]
                others = [s for s in signals if not s["event_keys"][0].startswith("rate:")]
                touched |= self.aggregator.persist(connection, others, ev, origin)
                for signal in rates:
                    touched |= self.aggregator.persist(connection, [signal], None, origin)
            if touched:
                self.aggregator.recompute(connection, touched)
            if origin == "live" and rows:
                store.meta_set(connection, "checkpoint", str(max(row["_rowid"] for row in rows)))
        self.terms.flush()
        self.state_store.count_suppression_matches(self.decider.take_matches())
        counts["detections"] = len(touched)
        return counts

    def drain(self, max_batches: int | None = None) -> dict[str, int]:
        total = {"events": 0, "signals": 0, "detections": 0, "batches": 0}
        threaded = threading.current_thread() is self._thread
        while max_batches is None or total["batches"] < max_batches:
            size = batch_size()
            if threaded:
                # Give way to the dashboard and the collector: wait (up to 2 s) while requests are
                # being served, and work in small batches (about 0.3 s each) so a request that
                # arrives meanwhile never waits behind a long one.
                busy.wait_until_idle(2.0, self._stop)
                size = min(size, 300)
                if self._stop.is_set():
                    break
            with self.lock:
                checkpoint = int(store.meta_get("checkpoint", "0") or 0)
                with db.read() as connection:
                    rows = connection.execute(
                        f"SELECT {EVENT_COLUMNS} FROM events WHERE rowid > ? ORDER BY rowid LIMIT ?",
                        (checkpoint, size)).fetchall()
                if not rows:
                    break
                started = time.perf_counter()
                counts = self.process_rows(rows)
                elapsed = time.perf_counter() - started
                if len(rows) < size and counts["detections"]:
                    # Caught up: drop cached counts now, so pages never show counts from mid-batch
                    # (while a large backlog is processed the short-lived cache keeps pages fast).
                    from . import queries
                    queries.invalidate()
            for key in ("events", "signals", "detections"):
                total[key] += counts[key]
            total["batches"] += 1
            self.stats["processed"] += counts["events"]
            self.stats["signals"] += counts["signals"]
            self.stats["batches"] += 1
            self.stats["last_batch_at"] = iso(utc_now())
            self.stats["last_batch_ms"] = round(elapsed * 1000, 1)
            self.stats["events_per_second"] = round(counts["events"] / elapsed, 1) if elapsed > 0 else None
            self._maybe_save_model()
        if total["events"]:
            from . import queries
            queries.invalidate()
        return total

    def backlog(self) -> int:
        """Events stored but not yet processed: MAX(rowid) - checkpoint.  Rowids only grow, so this is
        exact unless retention already removed unprocessed rows (then it over-counts until they are
        passed).  Counting the rows instead took 1-2 s on every dashboard poll during a large backlog."""
        checkpoint = int(store.meta_get("checkpoint", "0") or 0)
        with db.connect() as connection:
            row = connection.execute("SELECT MAX(rowid) FROM events").fetchone()
        return max(0, (row[0] or 0) - checkpoint)

    def replay(self) -> None:
        """Rebuild correlation state after a restart (no signals are stored again)."""
        checkpoint = int(store.meta_get("checkpoint", "0") or 0)
        if not checkpoint:
            return
        span = self._max_window()
        with db.connect() as connection:
            row = connection.execute("SELECT event_time FROM events WHERE rowid <= ? ORDER BY rowid DESC LIMIT 1",
                                     (checkpoint,)).fetchone()
        if not row:
            return
        newest = parse_time(row[0])
        if newest is None:
            return
        process_since = iso(newest - timedelta(hours=env_int("GRIFFENDO_PROCESS_TTL_HOURS", 24, 1)))
        window_since = iso(newest - timedelta(seconds=span))
        # The database lock is shared by every page, so rows are read a page at a time (the lock is
        # held only for each short read) and the work happens outside it, giving way to requests in
        # between.  v5.0 read and processed everything under the lock, which kept the dashboard from
        # answering for 30 s or more after a restart with history.
        threaded = threading.current_thread() is self._thread
        lineage_where = f"event_time >= ? AND event_time < ? AND rowid <= ? AND ({PROCESS_EVENTS})"
        for rows in self._paged(lineage_where, (process_since, window_since, checkpoint), 2000, threaded):
            with self.lock:
                for item in rows:
                    ev = normalizer.normalize(item)
                    self.state.observe(ev, epoch(ev["@timestamp"]))
        for rows in self._paged("event_time >= ? AND rowid <= ?", (window_since, checkpoint), 500, threaded):
            with self.lock:
                self.process_rows(rows, origin="replay", persist=False, use_behavior=False)
            self.stats["replayed"] += len(rows)

    def _paged(self, where: str, params: tuple, size: int, threaded: bool):
        """Rows of events matching `where`, oldest first, read in short keyset pages."""
        last_time, last_rowid = "", 0
        while not self._stop.is_set():
            if threaded:
                busy.wait_until_idle(2.0, self._stop)
            with db.read() as connection:
                rows = connection.execute(
                    f"SELECT {EVENT_COLUMNS} FROM events WHERE {where} "
                    f"AND (event_time > ? OR (event_time = ? AND rowid > ?)) ORDER BY event_time, rowid LIMIT ?",
                    (*params, last_time, last_time, last_rowid, size)).fetchall()
            if not rows:
                return
            yield rows
            last_time, last_rowid = rows[-1]["event_time"], rows[-1]["_rowid"]

    def _max_window(self) -> int:
        """Longest look-back the replay must rebuild: every rule window *and* the v6
        correlation horizon, so a restart restores occurrence series and open episodes
        exactly as they were (otherwise a series could restart its count after a restart)."""
        longest = 3600
        for rule in self.registry.rules.values():
            spec = rule.spec
            timeout = (spec.get("correlation") or {}).get("timeout_seconds")
            for value in ((spec.get("maxspan")), (spec.get("threshold") or {}).get("window_seconds"),
                          (spec.get("chain") or {}).get("window_seconds"),
                          (spec.get("wazuh") or {}).get("timeframe"), timeout):
                if isinstance(value, int):
                    longest = max(longest, value)
        longest = max(longest, self.correlator.bucketer.width * 2)
        return min(longest, 7 * 86400)

    def _maybe_save_model(self, force: bool = False) -> None:
        if self.behavior.dirty and (force or time.monotonic() - self._last_model_save > 30):
            self.behavior.state["updated_at"] = iso(utc_now())
            self.models.put("behavior", self.behavior.state)
            self.behavior.dirty = False
            self._last_model_save = time.monotonic()

    def _run(self) -> None:
        if self.replaying:
            try:
                self.replay()
            except Exception:
                self.stats["errors"] += 1
                self.stats["last_error"] = traceback.format_exc(limit=3)
            finally:
                self.replaying = False
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            try:
                self.drain()
            except Exception:
                self.stats["errors"] += 1
                self.stats["last_error"] = traceback.format_exc(limit=3)
                time.sleep(1)

    def notify(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
        with self.lock:
            self._maybe_save_model(force=True)
            self.terms.flush()
        self.models.close()
        self.state_store.close()

    # ------------------------------------------------------------------ rule switches and re-evaluation
    def set_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        rule = self.registry.get(rule_id)
        if rule is None:
            raise KeyError(rule_id)
        if rule.protected:
            raise reg.RuleError("This is a Wazuh grouping rule (level below 3): it never alerts itself and its child "
                                "rules depend on it, so it cannot be switched off.")
        with self.lock:
            if rule.origin == "custom":
                self.state_store.set_custom_enabled(rule_id, enabled)
            else:
                self.state_store.set_builtin_enabled(rule_id, enabled)
            rule.enabled = enabled
            self.registry.rebuild()
        job = self.start_job(rule_id, "enabled" if enabled else "disabled")
        return {"rule": rule.public(), "job": job}

    def start_job(self, rule_id: str, reason: str) -> dict[str, Any]:
        with self.jobs_lock:
            current = self.jobs.get(rule_id)
            if current and current["state"] in ("queued", "running"):
                current["rerun"] = reason
                return public_job(current)
            job = {"rule_id": rule_id, "reason": reason, "state": "queued", "started_at": iso(utc_now()),
                   "finished_at": None, "examined": 0, "signals": 0, "detections": 0, "error": None, "rerun": None}
            self.jobs[rule_id] = job
        threading.Thread(target=self._run_job, args=(job,), name=f"griffendo-reeval-{rule_id}", daemon=True).start()
        return public_job(job)

    def _run_job(self, job: dict[str, Any]) -> None:
        while True:
            job["state"] = "running"
            try:
                rule = self.registry.get(job["rule_id"])
                self._recompute_rule(job["rule_id"], job)
                if rule is not None and rule.enabled:
                    if rule.kind == "wazuh":
                        self._reconcile_wazuh(rule, job)
                    elif rule.kind != "behavior":
                        self._reevaluate(rule, job)
                elif rule is not None and rule.kind == "wazuh":
                    self._reconcile_wazuh(rule, job)
                job["state"] = "done"
            except Exception as error:
                job["state"], job["error"] = "failed", str(error)
            job["finished_at"] = iso(utc_now())
            from . import queries
            queries.invalidate()
            with self.jobs_lock:
                if job.get("rerun"):
                    job["reason"], job["rerun"] = job["rerun"], None
                    continue
                break

    def _recompute_rule(self, rule_id: str, job: dict[str, Any]) -> None:
        with db.connect() as connection:
            ids = [row[0] for row in connection.execute(
                "SELECT DISTINCT detection_id FROM det_signals WHERE rule_id = ? AND detection_id IS NOT NULL",
                (rule_id,))]
        for start in range(0, len(ids), 2000):
            with self.lock, db.connect() as connection:
                self.aggregator.recompute(connection, ids[start:start + 2000])
        job["detections"] += len(ids)

    def _window_rows(self, sources: list[dict[str, Any]], include_lineage: bool):
        since = iso(utc_now() - timedelta(days=window_days()))
        clauses, params = [], []
        for source in sources:
            ids = source.get("event_ids") or []
            if ids:
                clauses.append(f"(channel = ? COLLATE NOCASE AND event_id IN ({','.join('?' for _ in ids)}))")
                params += [source["channel"], *ids]
            else:
                clauses.append("(channel = ? COLLATE NOCASE)")
                params.append(source["channel"])
        if include_lineage:
            clauses.append(f"({PROCESS_EVENTS})")
        if not clauses:
            return
        last_time, last_rowid = "", 0
        while True:
            if threading.current_thread() is not threading.main_thread():
                busy.wait_until_idle(1.0, self._stop)     # look-back jobs give way to pages and ingest
            with db.read() as connection:
                rows = connection.execute(
                    f"SELECT {EVENT_COLUMNS} FROM events WHERE event_time >= ? AND ({' OR '.join(clauses)}) "
                    f"AND (event_time > ? OR (event_time = ? AND rowid > ?)) ORDER BY event_time, rowid LIMIT ?",
                    (since, *params, last_time, last_time, last_rowid, batch_size())).fetchall()
            if not rows:
                return
            yield rows
            last_time, last_rowid = rows[-1]["event_time"], rows[-1]["_rowid"]

    def _reevaluate(self, rule, job: dict[str, Any]) -> None:
        """Targeted look-back for one rule: only its sources, only the detection window, no duplicates."""
        private_state = StateManager()
        matcher = Matcher(private_state, self.terms)
        chains = ChainCorrelator(private_state)
        sources = list(rule.sources) + ([rule.spec["until"]] if rule.spec.get("until") else [])
        sources = [s for item in sources for s in (item.get("sources") or [item]) if "channel" in s]
        stage = self.behavior.state["stage"]
        for rows in self._window_rows(sources, include_lineage=rule.kind == "chain"):
            if self.registry.get(rule.id) is not rule or not rule.enabled:
                job["state"] = "cancelled"
                return
            produced = []
            for row in rows:
                ev = normalizer.normalize(row)
                t = epoch(ev["@timestamp"])
                key = private_state.observe(ev, t)
                if rule.kind == "chain":
                    signals = chains.evaluate(rule, ev, t, key)
                else:
                    signals = matcher.evaluate(rule, ev, t)
                for signal in signals:
                    self.decider.decide(signal, stage)
                if signals:
                    produced.append((ev, signals))
            job["examined"] += len(rows)
            with self.lock, db.connect() as connection:
                touched: set[str] = set()
                for ev, signals in produced:
                    touched |= self.aggregator.persist(connection, signals, ev, "reevaluation")
                if touched:
                    self.aggregator.recompute(connection, touched)
            job["signals"] += sum(len(s) for _, s in produced)
            self.terms.flush()

    def _reconcile_wazuh(self, rule, job: dict[str, Any]) -> None:
        """Re-run the Wazuh tree on the rule's channels: one final rule per event, as Wazuh does."""
        channels = rule.spec["wazuh"].get("channels") or []
        private_state = StateManager()
        tree = WazuhTree(self.registry.wazuh, private_state, self.terms)
        stage = self.behavior.state["stage"]
        for rows in self._window_rows([{"channel": c} for c in channels], include_lineage=False):
            produced, finals = [], {}
            for row in rows:
                ev = normalizer.normalize(row)
                signals = tree.evaluate(ev, epoch(ev["@timestamp"]))
                for signal in signals:
                    self.decider.decide(signal, stage)
                    finals[ev["_key"]] = signal["id"]
                if signals:
                    produced.append((ev, signals))
            job["examined"] += len(rows)
            keys = [row["id"] for row in rows]
            with self.lock, db.connect() as connection:
                touched: set[str] = set()
                for ev, signals in produced:
                    touched |= self.aggregator.persist(connection, signals, ev, "reevaluation")
                # Older Wazuh signals for these events that are no longer the tree's final answer.
                for start in range(0, len(keys), 400):
                    chunk = keys[start:start + 400]
                    for item in connection.execute(
                            "SELECT s.id, s.detection_id, s.event_keys FROM det_signals s JOIN det_event_index x "
                            "ON x.detection_id = s.detection_id WHERE x.event_key IN "
                            f"({','.join('?' for _ in chunk)}) AND s.kind = 'wazuh' AND s.decision = 'alert'", chunk):
                        event_keys = json.loads(item["event_keys"])
                        if len(event_keys) == 1 and event_keys[0] in chunk and finals.get(event_keys[0]) != item["id"]:
                            connection.execute("UPDATE det_signals SET decision = 'retracted' WHERE id = ?", (item["id"],))
                            touched.add(item["detection_id"])
                if touched:
                    self.aggregator.recompute(connection, touched)
            job["signals"] += sum(len(s) for _, s in produced)

    def job(self, rule_id: str) -> dict[str, Any] | None:
        job = self.jobs.get(rule_id)
        return public_job(job) if job else None

    def running_jobs(self) -> list[dict[str, Any]]:
        return [public_job(job) for job in self.jobs.values() if job["state"] in ("queued", "running")]

    def wait_job(self, rule_id: str, seconds: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + seconds
        with busy.waiting_for_engine():
            while time.monotonic() < deadline:
                job = self.jobs.get(rule_id)
                if not job or job["state"] not in ("queued", "running"):
                    break
                time.sleep(0.02)
        return self.job(rule_id)

    # ------------------------------------------------------------------ custom rules
    def save_custom(self, definition: dict[str, Any], rule_id: str | None = None) -> dict[str, Any]:
        spec = custom_spec(definition)
        rule = reg.Rule(spec, module="custom")
        with self.lock:
            if rule_id is None:
                if self.registry.get(rule.id) or rule.id in self.registry.retired:
                    raise reg.RuleError(f"A rule with id {rule.id} already exists.")
                self.state_store.create_custom(rule.id, definition, bool(definition.get("enabled", True)))
                rule.enabled = bool(definition.get("enabled", True))
            else:
                existing = self.registry.get(rule_id)
                if existing is None or existing.origin != "custom":
                    raise KeyError(rule_id)
                self.state_store.update_custom(rule_id, definition)
                rule.enabled = existing.enabled
            self.registry.replace(rule)
        job = self.start_job(rule.id, "created" if rule_id is None else "edited")
        return {"rule": rule.public(), "job": job}

    def delete_custom(self, rule_id: str) -> dict[str, Any]:
        rule = self.registry.get(rule_id)
        if rule is None or rule.origin != "custom":
            raise KeyError(rule_id)
        with self.lock:
            self.state_store.delete_custom(rule_id)
            self.registry.remove(rule_id)
        job = self.start_job(rule_id, "deleted")
        return {"deleted": rule_id, "job": job}

    # ------------------------------------------------------------------ feedback
    def set_status(self, detection_id: str, status: str, note: str | None) -> str:
        if status not in fb.STATUSES:
            raise ValueError(f"status must be one of {', '.join(fb.STATUSES)}")
        with db.connect() as connection:
            row = connection.execute("SELECT primary_rule_id FROM det_detections WHERE id = ?", (detection_id,)).fetchone()
            if not row:
                raise KeyError(detection_id)
            at = self.state_store.set(detection_id, status, note, row[0], 0, "")
            connection.execute("UPDATE det_detections SET status = ?, status_updated_at = ? WHERE id = ?",
                               (status, at, detection_id))
        return at

    def set_verdict(self, detection_id: str, verdict: str, note: str | None) -> dict[str, Any]:
        if verdict not in fb.VERDICTS:
            raise ValueError(f"verdict must be one of {', '.join(fb.VERDICTS)}")
        with db.connect() as connection:
            row = connection.execute("SELECT id FROM det_detections WHERE id = ?", (detection_id,)).fetchone()
            if not row:
                raise KeyError(detection_id)
            signals = connection.execute(
                "SELECT details_json FROM det_signals WHERE detection_id = ? AND source = 'behavior'",
                (detection_id,)).fetchall()
        applied: dict[str, Any] = {"model": None}
        if signals and verdict in ("false_positive", "benign", "true_positive"):
            parts = []
            for item in signals:
                parts += (json.loads(item[0]).get("behavior") or {}).get("parts") or []
            with self.lock:
                applied["model"] = self.behavior.feedback(verdict, parts)
                self._maybe_save_model(force=True)
            self.models.audit("feedback", {"detection_id": detection_id, "verdict": verdict, **applied["model"]})
        at = self.state_store.add_verdict(detection_id, verdict, note, applied)
        with db.connect() as connection:
            connection.execute("UPDATE det_detections SET verdict = ? WHERE id = ?", (verdict, detection_id))
        return {"verdict": verdict, "at": at, "applied": applied}

    def suppress(self, detection_id: str, reason: str) -> dict[str, Any]:
        if not reason or len(reason.strip()) < 5:
            raise ValueError("Give a reason (at least 5 characters) for the suppression.")
        with db.connect() as connection:
            signals = connection.execute(
                "SELECT id, rule_id, evidence_json FROM det_signals WHERE detection_id = ? AND decision = 'alert' "
                "AND source != 'behavior'", (detection_id,)).fetchall()
        if not signals:
            raise ValueError("This detection has no active rule signal to suppress.")
        created = []
        for item in signals:
            events = [{**ev, "_key": ev.get("event_key"), "_lower": {}} for ev in json.loads(item["evidence_json"])]
            fp, fields = dec.fingerprint(item["rule_id"], events)
            suppression_id = f"SUP-{fp[:12]}"
            self.state_store.add_suppression(suppression_id, item["rule_id"], fp, fields, reason.strip(), detection_id)
            created.append({"id": suppression_id, "rule_id": item["rule_id"], "fields": fields})
        with self.lock:
            self.decider.load(self.state_store.suppressions())
            with db.connect() as connection:
                for item in signals:
                    events = [{**ev, "_key": ev.get("event_key"), "_lower": {}} for ev in json.loads(item["evidence_json"])]
                    fp, _ = dec.fingerprint(item["rule_id"], events)
                    connection.execute("UPDATE det_signals SET decision = 'suppressed', suppression_id = ? WHERE id = ?",
                                       (f"SUP-{fp[:12]}", item["id"]))
                self.aggregator.recompute(connection, [detection_id])
        from . import queries
        queries.invalidate()
        return {"created": created}

    def revoke_suppression(self, suppression_id: str) -> bool:
        ok = self.state_store.revoke_suppression(suppression_id)
        with self.lock:
            self.decider.load(self.state_store.suppressions())
            with db.connect() as connection:
                ids = [row[0] for row in connection.execute(
                    "SELECT detection_id FROM det_signals WHERE suppression_id = ?", (suppression_id,))]
                connection.execute("UPDATE det_signals SET decision = 'alert', suppression_id = NULL "
                                   "WHERE suppression_id = ?", (suppression_id,))
                self.aggregator.recompute(connection, set(ids))
        from . import queries
        queries.invalidate()
        return ok

    def reset_model(self) -> dict[str, Any]:
        with self.lock:
            version = self.behavior.state.get("baseline_version", 1) + 1
            self.behavior = beh.BehaviorModel()
            self.behavior.state["baseline_version"] = version
            self.behavior.state["stage_reason"] = "Baseline reset by the analyst; detection history kept."
            self.behavior.dirty = True
            self._maybe_save_model(force=True)
        self.models.audit("reset", {"baseline_version": version})
        return self.behavior.status()


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in job.items() if k != "rerun"}


def custom_spec(definition: dict[str, Any]) -> dict[str, Any]:
    """Stored custom-rule definition -> engine rule spec (validated by the registry)."""
    spec = {key: definition.get(key) for key in ("name", "description", "category", "severity", "condition",
                                                 "sources", "threshold", "steps", "maxspan", "mitre",
                                                 "investigation", "explanation", "risk_score", "tags",
                                                 "false_positives", "references", "author", "notes")}
    spec = {key: value for key, value in spec.items() if value is not None}
    spec.update(id=definition["rule_id"], kind=definition.get("kind", "single"), origin="custom",
                confidence="medium", enabled=bool(definition.get("enabled", True)),
                created_at=definition.get("created_at"), modified_at=definition.get("modified_at"),
                support={"status": "custom", "notes": "User-defined rule: not verified by Griffendo."},
                source={"platform": "User-defined", "license": "n/a", "author": definition.get("author")})
    if spec["kind"] == "sequence":
        spec["steps"] = [{**step, "sources": step.get("sources") or definition.get("sources") or []}
                         for step in spec.get("steps") or []]
    return spec


_SERVICE: DetectionService | None = None
_SERVICE_LOCK = threading.Lock()


def service(start_worker: bool = True) -> DetectionService:
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = DetectionService(start_worker=start_worker)
        return _SERVICE


def service_if_ready() -> DetectionService | None:
    """The running service, or None while it is still starting (never waits)."""
    return _SERVICE


def shutdown() -> None:
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is not None:
            _SERVICE.stop()
            _SERVICE = None
