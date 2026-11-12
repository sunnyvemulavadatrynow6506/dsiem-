"""Self-paced behaviour model for the local host.

Features (only from data Griffendo actually collects; network bytes, destination
reputation and similar are not collected and are not modelled):

  categorical  parent>child process pair, process name, user|process, user|logon type,
               user|logon source address, service name (7045/4697), scheduled task name (4698),
               channel|event id                       -> frequency tables with decay
  numeric      command-line length, command-line entropy -> exponentially weighted mean/variance
  rates        events/minute, process starts/minute, failed logons/5 min, error events/5 min
               (upward deviation of a closed bucket)  -> exponentially weighted mean/variance
  temporal     hour of day per user for logons and process starts -> per-user 24-bucket histogram

Scoring
  categorical rarity  r = -log((count + a) / (N + a*K)),  s = r / r_unseen      (unseen value -> 1)
  numeric deviation   z = (x - mean) / (sd + e),          s = min(|z| / z_max, 1)
  event score         S = sum(w_i * s_i) / sum(w_i)       over the features the event has
  risk                R = min(1, S * context)             context = 1.5 for a privileged logon session
                                                          (4672 seen), 1.3 for a host marked critical
                                                          (GRIFFENDO_CRITICAL_ASSET=1); 1 when unknown
  A missing feature is skipped: it never adds risk.

Learning (slow on purpose): mean <- (1 - lambda) * mean + lambda * x with lambda = 0.01 by default.
Only events whose behaviour score is below GRIFFENDO_BEHAVIOR_LEARN_MAX and that no rule
flagged at Medium or above update the baseline (baseline-poisoning guard); counts decay
by GRIFFENDO_BEHAVIOR_DECAY per day so old behaviour fades.

Lifecycle: learn -> shadow -> active, active -> adapt (moderate drift, faster learning) and
back, active/adapt -> shadow (large drift).  Deterministic rules are never affected by it.
"""
from __future__ import annotations

import math
import os
from datetime import datetime, timezone
from typing import Any

from ...settings import iso
from .conditions import entropy
from .normalizer import entity

STAGES = ("learn", "shadow", "active", "adapt")
CAT_WEIGHTS = {"parent_child": 1.0, "process": 0.6, "user_process": 0.5, "logon_type": 0.8, "logon_source": 0.8,
               "service": 1.0, "task": 0.9, "event_type": 0.3}
NUM_WEIGHTS = {"cmdline_length": 0.4, "cmdline_entropy": 0.6}
HIST_WEIGHTS = {"user_hour": 0.4, "logon_hour": 0.6}
RATES = {"events_per_minute": 60, "process_starts_per_minute": 60, "failed_logons_5m": 300, "errors_5m": 300}
FAMILY = {"parent_child": "process", "process": "process", "user_process": "process", "cmdline_length": "process",
          "cmdline_entropy": "process", "user_hour": "process", "logon_type": "logon", "logon_source": "logon",
          "logon_hour": "logon", "service": "persistence", "task": "persistence", "event_type": "volume"}
RULE_FOR_FAMILY = {"process": "BEH-PROCESS", "logon": "BEH-LOGON", "persistence": "BEH-PERSISTENCE",
                   "volume": "BEH-VOLUME"}
MAX_VALUES = 5000
ALPHA = 1.0
Z_MAX = 6.0


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def config() -> dict[str, Any]:
    return {
        "lambda": _env_float("GRIFFENDO_BEHAVIOR_LAMBDA", 0.01),
        "decay_per_day": _env_float("GRIFFENDO_BEHAVIOR_DECAY", 0.98),
        "alert_threshold": _env_float("GRIFFENDO_BEHAVIOR_ALERT_THRESHOLD", 0.6),
        "learn_max": _env_float("GRIFFENDO_BEHAVIOR_LEARN_MAX", 0.5),
        "min_observations": int(_env_float("GRIFFENDO_BEHAVIOR_MIN_OBSERVATIONS", 5000)),
        "min_learning_days": _env_float("GRIFFENDO_BEHAVIOR_MIN_LEARNING_DAYS", 2),
        "stable_novelty": _env_float("GRIFFENDO_BEHAVIOR_STABLE_NOVELTY", 0.05),
        "stable_variance_change": _env_float("GRIFFENDO_BEHAVIOR_STABLE_VARIANCE", 0.25),
        "min_shadow_hours": _env_float("GRIFFENDO_BEHAVIOR_MIN_SHADOW_HOURS", 24),
        "shadow_target_per_1000": _env_float("GRIFFENDO_BEHAVIOR_SHADOW_TARGET", 2.0),
        "shadow_max_fp_ratio": _env_float("GRIFFENDO_BEHAVIOR_SHADOW_MAX_FP", 0.3),
        "drift_moderate": _env_float("GRIFFENDO_BEHAVIOR_DRIFT_MODERATE", 3.0),
        "drift_large": _env_float("GRIFFENDO_BEHAVIOR_DRIFT_LARGE", 10.0),
        "critical_asset": os.getenv("GRIFFENDO_CRITICAL_ASSET", "0") == "1",
    }


def empty_state() -> dict[str, Any]:
    return {"version": 1, "stage": "learn", "stage_since": None, "stage_reason": "New baseline.",
            "observations": 0, "first_time": None, "last_time": None, "cat": {}, "num": {}, "hist": {},
            "rates": {}, "novelty": {"hour": None, "new": 0, "obs": 0, "baseline": None, "last_ratio": None},
            "checkpoints": [], "shadow": {"since": None, "would_alert": 0, "observations": 0},
            "verdicts": {"fp": 0, "tp": 0, "benign": 0}, "blocked": {}, "threshold_offset": 0.0,
            "baseline_version": 1, "updated_at": None, "adapt_until": None, "history": []}


class BehaviorModel:
    def __init__(self, state: dict[str, Any] | None = None):
        self.state = state or empty_state()
        for key, value in empty_state().items():
            self.state.setdefault(key, value)
        self.cfg = config()
        self.dirty = False

    # ------------------------------------------------------------------ features
    def features(self, ev: dict[str, Any]) -> dict[str, dict[str, Any]]:
        code = ev.get("winlog.event_id")
        channel = (ev.get("winlog.channel") or "").lower()
        ent = entity(ev)
        user = ent.get("user")
        out: dict[str, dict[str, Any]] = {"cat": {}, "num": {}, "hist": {}}
        out["cat"]["event_type"] = f"{channel}|{code}"
        hour = _hour(ev["@timestamp"])
        is_start = (channel.endswith("sysmon/operational") and code == 1) or (channel == "security" and code == 4688)
        if is_start:
            name = (ev.get("process.name") or "").lower()
            parent = (ev.get("process.parent.name") or "").lower()
            if name:
                out["cat"]["process"] = name
                if parent:
                    out["cat"]["parent_child"] = f"{parent}>{name}"
                if user:
                    out["cat"]["user_process"] = f"{user}|{name}"
            command = ev.get("process.command_line")
            if command:
                out["num"]["cmdline_length"] = float(len(command))
                out["num"]["cmdline_entropy"] = entropy(command)
            if user:
                out["hist"]["user_hour"] = (user, hour)
        elif channel == "security" and code == 4624 and user:
            logon_type = ev.get("winlog.logon.type")
            if logon_type:
                out["cat"]["logon_type"] = f"{user}|{logon_type}"
            source = ev.get("source.ip")
            if source and source not in ("-", "::1", "127.0.0.1"):
                out["cat"]["logon_source"] = f"{user}|{source}"
            out["hist"]["logon_hour"] = (user, hour)
        elif (channel == "system" and code == 7045) or (channel == "security" and code == 4697):
            service = ev.get("service.name")
            if service:
                out["cat"]["service"] = service.lower()
        elif channel == "security" and code == 4698:
            task = ev.get("scheduled_task.name")
            if task:
                out["cat"]["task"] = task.lower()
        return out

    # ------------------------------------------------------------------ scoring
    def _cat_score(self, name: str, value: str) -> tuple[float, bool]:
        table = self.state["cat"].get(name)
        if not table:
            return 1.0, True
        count = table["counts"].get(value, 0.0)
        total = table["total"]
        k = max(len(table["counts"]), 1)
        rarity = -math.log((count + ALPHA) / (total + ALPHA * k))
        unseen = -math.log(ALPHA / (total + ALPHA * k))
        return (min(rarity / unseen, 1.0) if unseen > 0 else 0.0), count == 0

    def _num_score(self, name: str, value: float) -> float | None:
        stats = self.state["num"].get(name)
        if not stats or stats["n"] < 30:
            return None
        sd = math.sqrt(max(stats["var"], 0.0))
        z = (value - stats["mean"]) / (sd + 1e-6)
        return min(abs(z) / Z_MAX, 1.0)

    def _hist_score(self, name: str, user: str, hour: int) -> float | None:
        table = self.state["hist"].get(name, {}).get(user)
        if not table or sum(table) < 20:
            return None
        total = sum(table)
        rarity = -math.log((table[hour] + ALPHA) / (total + ALPHA * 24))
        unseen = -math.log(ALPHA / (total + ALPHA * 24))
        return min(rarity / unseen, 1.0)

    def score(self, ev: dict[str, Any], features: dict[str, dict[str, Any]], privileged: bool) -> dict[str, Any]:
        parts: list[dict[str, Any]] = []
        for name, value in features["cat"].items():
            s, new = self._cat_score(name, value)
            parts.append({"feature": name, "value": value, "score": round(s, 3), "weight": CAT_WEIGHTS[name],
                          "new": new})
        for name, value in features["num"].items():
            s = self._num_score(name, value)
            if s is not None:
                stats = self.state["num"][name]
                parts.append({"feature": name, "value": round(value, 2), "score": round(s, 3),
                              "weight": NUM_WEIGHTS[name], "mean": round(stats["mean"], 2),
                              "sd": round(math.sqrt(max(stats["var"], 0)), 2)})
        for name, (user, hour) in features["hist"].items():
            s = self._hist_score(name, user, hour)
            if s is not None:
                parts.append({"feature": name, "value": f"{user} at {hour:02d}:00 UTC", "score": round(s, 3),
                              "weight": HIST_WEIGHTS[name]})
        if not parts:
            return {"S": 0.0, "R": 0.0, "parts": [], "context": 1.0}
        weight = sum(p["weight"] for p in parts)
        S = sum(p["weight"] * p["score"] for p in parts) / weight
        context = 1.0
        notes = []
        if privileged:
            context *= 1.5
            notes.append("privileged logon session (4672) x1.5")
        if self.cfg["critical_asset"]:
            context *= 1.3
            notes.append("host marked critical x1.3")
        return {"S": round(S, 4), "R": round(min(1.0, S * context), 4), "parts": parts, "context": round(context, 2),
                "context_notes": notes}

    def threshold(self) -> float:
        return min(0.95, max(0.3, self.cfg["alert_threshold"] + self.state.get("threshold_offset", 0.0)))

    # ------------------------------------------------------------------ learning
    def learn(self, features: dict[str, dict[str, Any]], t: float, result: dict[str, Any]) -> bool:
        """Update the baseline from one event (False when the event is not eligible)."""
        stage = self.state["stage"]
        flagged = result.get("rule_flagged")
        if flagged:
            return False
        if stage != "learn" and result.get("R", 0.0) >= self.cfg["learn_max"]:
            return False
        blocked = self.state["blocked"]
        rate = self.cfg["lambda"] * (5 if stage == "adapt" else 1)
        day = int(t // 86400)
        new_values = 0
        for name, value in features["cat"].items():
            if value in blocked.get(name, ()):
                continue
            table = self.state["cat"].setdefault(name, {"counts": {}, "total": 0.0, "day": day})
            if table["day"] != day:
                factor = self.cfg["decay_per_day"] ** max(0, day - table["day"])
                if factor < 1:
                    table["counts"] = {k: v * factor for k, v in table["counts"].items() if v * factor >= 0.05}
                    table["total"] = sum(table["counts"].values())
                table["day"] = max(day, table["day"])
            if value not in table["counts"]:
                new_values += 1
            table["counts"][value] = table["counts"].get(value, 0.0) + 1
            table["total"] += 1
            if len(table["counts"]) > MAX_VALUES:
                smallest = sorted(table["counts"].items(), key=lambda item: item[1])[:len(table["counts"]) - MAX_VALUES]
                for key, count in smallest:
                    del table["counts"][key]
                    table["total"] -= count
        for name, value in features["num"].items():
            stats = self.state["num"].setdefault(name, {"mean": 0.0, "var": 0.0, "n": 0})
            self._update_stats(stats, value, rate)
        for name, (user, hour) in features["hist"].items():
            table = self.state["hist"].setdefault(name, {}).setdefault(user, [0.0] * 24)
            table[hour] += 1
            if len(self.state["hist"][name]) > MAX_VALUES:
                self.state["hist"][name].pop(next(iter(self.state["hist"][name])))
        self._novelty(t, new_values, 1)
        self.state["observations"] += 1
        if self.state["first_time"] is None or t < self.state["first_time"]:
            self.state["first_time"] = t
        if self.state["last_time"] is None or t > self.state["last_time"]:
            self.state["last_time"] = t
        self.dirty = True
        return True

    @staticmethod
    def _update_stats(stats: dict[str, Any], value: float, rate: float) -> None:
        stats["n"] += 1
        if stats["n"] <= 100:
            # Welford until the estimate is meaningful, then the slow exponential update.
            delta = value - stats["mean"]
            stats["mean"] += delta / stats["n"]
            stats["var"] += (delta * (value - stats["mean"]) - stats["var"]) / stats["n"]
        else:
            delta = value - stats["mean"]
            stats["mean"] += rate * delta
            stats["var"] = (1 - rate) * (stats["var"] + rate * delta * delta)

    def _novelty(self, t: float, new: int, obs: int) -> None:
        hour = int(t // 3600)
        novelty = self.state["novelty"]
        if novelty["hour"] is None:
            novelty["hour"] = hour
        if hour > novelty["hour"]:
            self._close_hour()
            novelty["hour"], novelty["new"], novelty["obs"] = hour, 0, 0
        if hour == novelty["hour"]:
            novelty["new"] += new
            novelty["obs"] += obs

    def _close_hour(self) -> None:
        novelty = self.state["novelty"]
        if novelty["obs"] < 20:
            return
        rate = novelty["new"] / novelty["obs"]
        baseline = novelty["baseline"]
        novelty["last_ratio"] = None if baseline is None else rate / max(baseline, 0.005)
        novelty["last_new"] = novelty["new"]
        novelty["baseline"] = rate if baseline is None else 0.9 * baseline + 0.1 * rate
        checkpoints = self.state["checkpoints"]
        checkpoints.append({"hour": novelty["hour"], "novelty": round(rate, 4),
                            "var": {k: round(v["var"], 4) for k, v in self.state["num"].items()}})
        del checkpoints[:-48]

    # ------------------------------------------------------------------ rates
    def rate_events(self, ev: dict[str, Any], t: float) -> list[dict[str, Any]]:
        """Close finished rate buckets; returns deviations for closed buckets."""
        code = ev.get("winlog.event_id")
        channel = (ev.get("winlog.channel") or "").lower()
        increments = {"events_per_minute": True,
                      "process_starts_per_minute": (channel.endswith("sysmon/operational") and code == 1)
                      or (channel == "security" and code == 4688),
                      "failed_logons_5m": channel == "security" and code == 4625,
                      "errors_5m": ev.get("log.level") in ("Error", "Critical")}
        findings = []
        for name, size in RATES.items():
            bucket = int(t // size)
            current = self.state["rates"].setdefault(name, {"bucket": bucket, "count": 0, "stats": {"mean": 0.0,
                                                                                                    "var": 0.0, "n": 0},
                                                             "sample": []})
            if bucket < current["bucket"]:
                continue    # late event for a closed bucket: not counted (documented)
            if bucket > current["bucket"]:
                finding = self._close_bucket(name, current)
                if finding:
                    findings.append(finding)
                gap = min(bucket - current["bucket"] - 1, 60)
                for _ in range(gap):
                    self._update_stats(current["stats"], 0.0, self.cfg["lambda"])
                current.update(bucket=bucket, count=0, sample=[])
            if increments[name]:
                current["count"] += 1
                if len(current["sample"]) < 10:
                    current["sample"].append(ev["_key"])
        return findings

    def _close_bucket(self, name: str, current: dict[str, Any]) -> dict[str, Any] | None:
        stats = current["stats"]
        value = float(current["count"])
        finding = None
        if stats["n"] >= 60 and value > 0:
            sd = math.sqrt(max(stats["var"], 0.0))
            z = (value - stats["mean"]) / (sd + 1e-6)
            if z > 0:
                s = min(z / Z_MAX, 1.0)
                finding = {"feature": name, "value": value, "mean": round(stats["mean"], 2), "sd": round(sd, 2),
                           "score": round(s, 3), "bucket_start": iso(datetime.fromtimestamp(
                               current["bucket"] * RATES[name], tz=timezone.utc)), "bucket_seconds": RATES[name],
                           "sample": list(current["sample"])}
        if finding is None or finding["score"] < self.cfg["learn_max"] or self.state["stage"] == "learn":
            self._update_stats(stats, value, self.cfg["lambda"])
        self.dirty = True
        return finding

    # ------------------------------------------------------------------ lifecycle
    def lifecycle(self, t: float) -> dict[str, Any] | None:
        """Promote / demote the model; returns the change (for the audit log) or None."""
        stage = self.state["stage"]
        cfg = self.cfg
        change = None
        if self.state["stage_since"] is None:
            self.state["stage_since"] = t
        if stage == "learn":
            obs = self.state["observations"]
            span_days = ((self.state["last_time"] or t) - (self.state["first_time"] or t)) / 86400
            checkpoints = self.state["checkpoints"][-6:]
            novelty_ok = len(checkpoints) >= 3 and max(c["novelty"] for c in checkpoints[-3:]) <= cfg["stable_novelty"]
            variance_ok = True
            if len(checkpoints) >= 2:
                a, b = checkpoints[-2]["var"], checkpoints[-1]["var"]
                for key in set(a) & set(b):
                    if a[key] > 0 and abs(b[key] - a[key]) / a[key] > cfg["stable_variance_change"]:
                        variance_ok = False
            if obs >= cfg["min_observations"] and span_days >= cfg["min_learning_days"] and novelty_ok and variance_ok:
                change = self._move("shadow", t, f"Baseline built from {obs} observations over {span_days:.1f} days; "
                                                 "new-value rate and variance are stable.")
                self.state["shadow"] = {"since": t, "would_alert": 0, "observations": 0}
        elif stage == "shadow":
            shadow = self.state["shadow"]
            hours = (t - (shadow["since"] or t)) / 3600
            per_1000 = 1000 * shadow["would_alert"] / max(shadow["observations"], 1)
            verdicts = self.state["verdicts"]
            judged = verdicts["fp"] + verdicts["benign"] + verdicts["tp"]
            fp_ratio = (verdicts["fp"] + verdicts["benign"]) / judged if judged else 0.0
            if hours >= cfg["min_shadow_hours"] and shadow["observations"] >= 500 \
                    and per_1000 <= cfg["shadow_target_per_1000"] and fp_ratio <= cfg["shadow_max_fp_ratio"]:
                change = self._move("active", t, f"Shadow run of {hours:.0f} h: {per_1000:.2f} would-be alerts per "
                                                 f"1,000 observations (target <= {cfg['shadow_target_per_1000']}).")
        elif stage in ("active", "adapt"):
            novelty = self.state["novelty"]
            ratio = novelty.get("last_ratio")
            new = novelty.get("last_new", 0)
            if ratio is not None and ratio >= cfg["drift_large"] and new >= 20:
                change = self._move("shadow", t, f"Large behaviour drift (new-value rate x{ratio:.1f} of baseline): "
                                                 "back to shadow until the baseline re-stabilises.")
                self.state["shadow"] = {"since": t, "would_alert": 0, "observations": 0}
            elif stage == "active" and ratio is not None and ratio >= cfg["drift_moderate"] and new >= 10:
                change = self._move("adapt", t, f"Moderate drift (x{ratio:.1f}); learning 5x faster for 2 hours.")
                self.state["adapt_until"] = t + 7200
            elif stage == "adapt" and t >= (self.state.get("adapt_until") or 0) and (ratio is None or
                                                                                     ratio < cfg["drift_moderate"]):
                change = self._move("active", t, "Drift subsided.")
        return change

    def _move(self, stage: str, t: float, reason: str) -> dict[str, Any]:
        previous = self.state["stage"]
        self.state.update(stage=stage, stage_since=t, stage_reason=reason)
        entry = {"from": previous, "to": stage, "at": iso(datetime.fromtimestamp(t, tz=timezone.utc)),
                 "reason": reason}
        self.state["history"] = (self.state.get("history") or [])[-49:] + [entry]
        self.dirty = True
        return entry

    # ------------------------------------------------------------------ feedback
    def feedback(self, verdict: str, parts: list[dict[str, Any]]) -> dict[str, Any]:
        """Apply an analyst verdict on a behaviour detection (narrow: only the exact feature values)."""
        applied: dict[str, Any] = {"verdict": verdict, "changes": []}
        key = {"false_positive": "fp", "benign": "benign", "true_positive": "tp"}.get(verdict)
        if key:
            self.state["verdicts"][key] += 1
        for part in parts:
            name = part.get("feature")
            value = part.get("value")
            if name not in CAT_WEIGHTS or not isinstance(value, str):
                continue
            if verdict in ("false_positive", "benign"):
                table = self.state["cat"].setdefault(name, {"counts": {}, "total": 0.0, "day": 0})
                table["counts"][value] = table["counts"].get(value, 0.0) + 5
                table["total"] += 5
                applied["changes"].append(f"{name}={value}: +5 observations (known good)")
            elif verdict == "true_positive":
                self.state["blocked"].setdefault(name, [])
                if value not in self.state["blocked"][name]:
                    self.state["blocked"][name].append(value)
                applied["changes"].append(f"{name}={value}: never learned as normal")
        recent = self.state.setdefault("recent_verdicts", [])
        recent.append(key or verdict)
        del recent[:-20]
        if len(recent) >= 10:
            fp = sum(1 for item in recent if item in ("fp", "benign")) / len(recent)
            if fp > 0.5 and self.state["threshold_offset"] < 0.25:
                self.state["threshold_offset"] = round(self.state["threshold_offset"] + 0.05, 2)
                applied["changes"].append(f"alert threshold raised to {self.threshold():.2f} "
                                          f"({fp:.0%} of the last {len(recent)} verdicts were false/benign)")
                recent.clear()
        self.dirty = True
        return applied

    def status(self) -> dict[str, Any]:
        s = self.state
        span = ((s["last_time"] or 0) - (s["first_time"] or 0)) / 86400 if s["first_time"] else 0
        cfg = self.cfg
        progress = {
            "observations": s["observations"], "required_observations": cfg["min_observations"],
            "days": round(span, 2), "required_days": cfg["min_learning_days"],
            "recent_novelty": [c["novelty"] for c in s["checkpoints"][-6:]],
            "novelty_target": cfg["stable_novelty"],
        }
        shadow = s["shadow"]
        if s["stage"] == "shadow" and shadow.get("since"):
            progress.update(shadow_hours=round(((s["last_time"] or 0) - shadow["since"]) / 3600, 1),
                            required_shadow_hours=cfg["min_shadow_hours"],
                            shadow_would_alert=shadow["would_alert"], shadow_observations=shadow["observations"],
                            shadow_target_per_1000=cfg["shadow_target_per_1000"])
        return {
            "stage": s["stage"], "stage_reason": s.get("stage_reason"),
            "stage_since": _fmt(s.get("stage_since")), "observations": s["observations"],
            "first_observation": _fmt(s["first_time"]), "last_observation": _fmt(s["last_time"]),
            "updated_at": s.get("updated_at"), "baseline_version": s.get("baseline_version", 1),
            "alert_threshold": round(self.threshold(), 2), "features": {
                "categorical": {k: {"values": len(v["counts"]), "observations": round(v["total"])}
                                for k, v in s["cat"].items()},
                "numeric": {k: {"mean": round(v["mean"], 2), "sd": round(math.sqrt(max(v["var"], 0)), 2), "n": v["n"]}
                            for k, v in s["num"].items()},
                "temporal": {k: len(v) for k, v in s["hist"].items()},
                "rates": {k: {"mean": round(v["stats"]["mean"], 2), "n": v["stats"]["n"]} for k, v in s["rates"].items()},
            },
            "unavailable_features": ["network bytes", "destination reputation", "file reputation / signatures",
                                     "process memory or API activity"],
            "progress": progress, "verdicts": dict(s["verdicts"]), "blocked_values": sum(len(v) for v in s["blocked"].values()),
            "history": (s.get("history") or [])[-10:], "drift_ratio": s["novelty"].get("last_ratio"),
        }


def _hour(stamp: str) -> int:
    try:
        return int(stamp[11:13])
    except (TypeError, ValueError):
        return 0


def _fmt(value: float | None) -> str | None:
    return iso(datetime.fromtimestamp(value, tz=timezone.utc)) if value else None
