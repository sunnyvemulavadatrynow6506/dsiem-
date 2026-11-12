"""Decide, per rule and per event source, whether a translated condition can be evaluated on local data.

Partial evaluation over a source: fields whose value is fixed for the source
(event.code, winlog.channel, event.category/type/action, data_stream.dataset,
host.os.type) are replaced by their possible values; fields the source can never
carry evaluate to False (exactly what happens at run time, because a predicate
on a missing field is false).  The result for the whole condition is
True / False / Unknown.  A source survives unless the result is False.

Every predicate on an unavailable field is recorded with its polarity:
  * positive  -> a branch that can no longer match (detection narrower, no new false positives)
  * negated   -> an exclusion that can no longer apply (detection broader: more false positives possible)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from logplatform.detection.engine import conditions, normalizer, schema  # noqa: E402

T, F, U = "T", "F", "U"

OPTIONAL_CHANNELS = {
    schema.SYSMON: "Sysmon (Microsoft-Windows-Sysmon/Operational) installed and collected",
    schema.POWERSHELL: "PowerShell script block logging (Microsoft-Windows-PowerShell/Operational 4104)",
}
# Events Windows writes only on domain controllers (local to the host only when Griffendo runs on a DC).
DC_EVENTS = {4662, 4768, 4769, 4770, 4771, 5136, 5137, 5138, 5139, 5141, 4741, 4742, 4743, 4765, 4766, 4780, 4794}
REQUIRES_POLICY = {
    4688: "Audit Process Creation (and 'Include command line in process creation events' for command-line conditions)",
    4689: "Audit Process Termination", 4656: "Audit Handle Manipulation / object SACLs", 4663: "Object access auditing and SACLs",
    4657: "Registry auditing (SACLs)", 5145: "Audit Detailed File Share", 5140: "Audit File Share",
    4662: "Directory Service Access auditing (domain controllers)", 5136: "Directory Service Changes auditing (domain controllers)",
    4698: "Audit Other Object Access Events", 4702: "Audit Other Object Access Events",
    5156: "Audit Filtering Platform Connection", 4674: "Audit Sensitive Privilege Use", 4673: "Audit Sensitive Privilege Use",
}


def constants(key: str, channel: str, event_id: int | None) -> dict[str, list[Any]]:
    """Possible values of the source-fixed fields."""
    result: dict[str, list[Any]] = {
        "winlog.channel": [channel], "host.os.type": ["windows"], "host.os.family": ["windows"],
        "event.kind": ["event"],
    }
    dataset = next((value for name, value in schema.DATASETS.items() if name.lower() == channel.lower()), None)
    result["data_stream.dataset"] = [dataset] if dataset else []
    if key in schema.SOURCES:
        source = schema.SOURCES[key]
        ids = source["event_ids"] if event_id is None else [event_id]
        result["event.code"] = [str(i) for i in ids]
        result["winlog.event_id"] = list(ids)
        for name, values in source["ecs"].items():
            result[name] = list(values)
        if key == "powershell:4104":
            result["event.provider"] = ["Microsoft-Windows-PowerShell"]
        elif channel == schema.SYSMON:
            result["event.provider"] = ["Microsoft-Windows-Sysmon"]
        return result
    if event_id is None:
        return result
    result["event.code"] = [str(event_id)]
    result["winlog.event_id"] = [event_id]
    if channel.lower() == "security":
        category = normalizer.SECURITY_CATEGORY.get(event_id)
        result["event.category"] = list(category[0]) if category else []
        result["event.type"] = list(category[1]) if category else []
        action = normalizer.SECURITY_ACTIONS.get(event_id)
        result["event.action"] = [action] if action else []
    elif channel.lower() == "system" and event_id == 7045:
        result["event.action"] = ["service-installed"]
        result["event.category"], result["event.type"] = ["configuration"], ["creation"]
    elif channel.lower() == "system" and event_id == 104:
        result["event.action"] = ["Log clear"]
        result["event.category"], result["event.type"] = [], []
    else:
        result["event.action"], result["event.category"], result["event.type"] = [], [], []
    return result


class Analysis:
    def __init__(self, key: str, channel: str, event_id: int | None):
        self.key, self.channel, self.event_id = key, channel, event_id
        self.consts = constants(key, channel, event_id)
        self.lost_positive: set[str] = set()
        self.lost_exclusion: set[str] = set()

    def available(self, field: str) -> bool:
        if field in self.consts:
            return True
        return schema.field_available(field, self.key, self.channel)

    def run(self, node: dict[str, Any], negated: bool = False) -> str:
        if "all" in node:
            results = [self.run(child, negated) for child in node["all"]]
            return F if F in results else (T if all(r == T for r in results) else U)
        if "any" in node:
            results = [self.run(child, negated) for child in node["any"]]
            return T if T in results else (F if all(r == F for r in results) else U)
        if "not" in node:
            inner = self.run(node["not"], not negated)
            return {T: F, F: T, U: U}[inner]
        if "const" in node:
            return T if node["const"] else F
        fields = [node["field"]] + ([node["other"]] if node.get("other") else [])
        for name in fields:
            base = name.removesuffix(".caseless")
            if base in self.consts:
                continue
            if not schema.field_available(base, self.key, self.channel):
                (self.lost_exclusion if negated else self.lost_positive).add(base)
                return F
        field = node["field"].removesuffix(".caseless")
        if field in self.consts and not node.get("other"):
            values = self.consts[field]
            if not values:
                return F
            predicate = conditions.compile_condition({**node, "field": field})
            outcomes = {predicate({field: value, "_lower": {}}) for value in values}
            return T if outcomes == {True} else (F if outcomes == {False} else U)
        return U


def plausible_channels(code: int) -> set[str]:
    """Channels an Event ID number belongs to when a rule names only the number (no channel / provider test)."""
    found = set()
    if 1100 <= code <= 1108 or 4608 <= code <= 4999 or 5024 <= code <= 5899 or 6144 <= code <= 6424:
        found.add(schema.SECURITY.lower())
    if code in (41, 104, 1074, 1076, 6005, 6006, 6008, 6009, 6013) or 7000 <= code <= 7099:
        found.add(schema.SYSTEM.lower())
    if 4100 <= code <= 4106:
        found.add(schema.POWERSHELL.lower())
    if code <= 29:
        found.add(schema.SYSMON.lower())
    if 1000 <= code <= 2050 or 3002 <= code <= 3007 or 5000 <= code <= 5013:
        found.add(schema.DEFENDER.lower())
    if code in (0, 1000, 1001, 1002, 11707, 11724) or 18000 <= code <= 18999:
        found.add(schema.APPLICATION.lower())
    return found


def candidate_sources(channels: set[str], category: str | None, codes: set[int]) -> list[tuple[str, str, int | None]]:
    """(source key, channel, event id) candidates for a rule."""
    out: list[tuple[str, str, int | None]] = []
    lowered = {c.lower() for c in channels}
    for key, source in schema.SOURCES.items():
        if source["channel"].lower() not in lowered:
            continue
        if category and category not in ("any",) and source["category"] != category:
            continue
        if codes and not (set(source["event_ids"]) & codes):
            continue
        ids = sorted(set(source["event_ids"]) & codes) if codes else [None]
        for eid in ids:
            out.append((key, source["channel"], eid))
    if category in (None, "any", "iam", "authentication", "configuration", "process", "file", "network", "registry",
                    "driver", "library"):
        specific = {(s["channel"].lower(), eid) for s in schema.SOURCES.values() for eid in s["event_ids"]}
        for channel in sorted(channels):
            for eid in sorted(codes):
                if (channel.lower(), eid) in specific:
                    continue
                if category in ("process", "file", "network", "registry", "driver", "library"):
                    continue
                if channel.lower() not in plausible_channels(eid):
                    continue
                out.append((f"generic:{channel}:{eid}", channel, eid))
    return out


def analyse(node: dict[str, Any], candidates: list[tuple[str, str, int | None]], extra_required: list[str] = ()) \
        -> list[dict[str, Any]]:
    """Per-candidate verdicts (only sources that can match are returned)."""
    results = []
    for key, channel, eid in candidates:
        analysis = Analysis(key, channel, eid)
        missing_joins = [name for name in extra_required if name != "host.id" and not analysis.available(name)]
        verdict = analysis.run(node)
        if verdict == F or missing_joins:
            continue
        results.append({"key": key, "channel": channel, "event_id": eid, "verdict": verdict,
                        "lost_positive": sorted(analysis.lost_positive),
                        "lost_exclusion": sorted(analysis.lost_exclusion)})
    return results


def rejected_reasons(node: dict[str, Any], candidates: list[tuple[str, str, int | None]],
                     extra_required: list[str] = ()) -> list[str]:
    reasons: set[str] = set()
    for key, channel, eid in candidates:
        analysis = Analysis(key, channel, eid)
        analysis.run(node)
        missing_joins = [name for name in extra_required if name != "host.id" and not analysis.available(name)]
        if missing_joins:
            reasons.add(f"join field(s) {', '.join(missing_joins)} not available from {channel}")
        reasons.update(f"required field {name} is not in any local Windows event" for name in analysis.lost_positive)
    return sorted(reasons)


def witness_event(node: dict[str, Any], key: str, channel: str, event_id: int | None) -> dict[str, Any] | None:
    """A normalized-looking event from this source that satisfies ``node`` (None if none was found)."""
    consts = constants(key, channel, event_id)
    predicate = conditions.compile_condition(node)
    base: dict[str, Any] = {"_key": "witness", "_raw": {}, "_lower": {}}
    for name, values in consts.items():
        if values:
            base[name] = values[0]
    if "event.type" in consts and consts["event.type"]:
        base["event.type"] = list(consts["event.type"][:1])
    if "event.category" in consts and consts["event.category"]:
        base["event.category"] = list(consts["event.category"])
    for candidate in conditions.witness_candidates(node, limit=96):
        event = dict(base)
        ok = True
        for name, value in candidate.items():
            if name in ("event.type", "event.category") and isinstance(value, list):
                value = value[0]
            if name in consts:
                if consts[name] and value not in consts[name] and str(value) not in [str(v) for v in consts[name]]:
                    # try a case-insensitive / list-membership match against the fixed values
                    matched = [v for v in consts[name] if str(v).lower() == str(value).lower()]
                    if not matched:
                        if name in ("event.type", "event.category"):
                            event[name] = [value]
                            continue
                        ok = False
                        break
                    value = matched[0]
                event[name] = [value] if name in ("event.type", "event.category") else value
                continue
            if name.startswith("winlog.event_data."):
                raw_name = name[len("winlog.event_data."):]
                event["_raw"] = {**event["_raw"], raw_name: value}
                event["_lower"] = {**event["_lower"], raw_name.lower(): value}
                continue
            event[name] = value
        if not ok:
            continue
        if predicate(event):
            return event
        # A second chance: multi-valued fields may need every listed element.
        if predicate({**event}):
            return event
    return None
