"""Inspect, classify and translate the Elastic detection rules (windows.zip, TOML)."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import availability as av
import eql
import kql
from eql import Unsupported

from logplatform.detection.engine import conditions, normalizer, schema

WINDOWS_INDEXES = {
    "winlogbeat-*": "*", "logs-windows.forwarded*": "*",
    "logs-windows.sysmon_operational-*": schema.SYSMON, "logs-system.security*": schema.SECURITY,
    "logs-system.security-*": schema.SECURITY, "logs-windows.powershell*": schema.POWERSHELL,
    "logs-windows.powershell_operational*": schema.POWERSHELL, "logs-system.system*": schema.SYSTEM,
    "logs-system.application*": schema.APPLICATION, "logs-system.application-*": schema.APPLICATION,
    "logs-windows.*": "*",
}
ALL_CHANNELS = {schema.SYSMON, schema.SECURITY, schema.SYSTEM, schema.APPLICATION, schema.POWERSHELL,
                schema.DEFENDER, schema.TASKS, schema.WMI}
EDR_INDEXES = ("logs-endpoint.", "endgame-", "logs-sentinel_one", "logs-crowdstrike", "logs-m365_defender", ".alerts-",
               "logs-microsoft_defender", "logs-sysmon_linux")
HOST_FIELDS = {"host.id", "host.name", "host.hostname", "winlog.computer_name", "agent.id"}
SEVERITY = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
# event.action values -> (channel, event id) for rules that name the action instead of the code.
ACTION_SOURCES: dict[str, list[tuple[str, int]]] = {}
for _eid, _action in normalizer.SECURITY_ACTIONS.items():
    ACTION_SOURCES.setdefault(_action, []).append((schema.SECURITY, _eid))
ACTION_SOURCES.setdefault("service-installed", []).append((schema.SYSTEM, 7045))
ACTION_SOURCES.setdefault("Log clear", []).append((schema.SYSTEM, 104))
ACTION_SOURCES_CI = {key.casefold(): value for key, value in ACTION_SOURCES.items()}
# event.category values -> Security event ids with that category (used when a rule names no Event ID).
CATEGORY_CODES: dict[str, set[int]] = {}
for _eid, (_cats, _types) in normalizer.SECURITY_CATEGORY.items():
    for _cat in _cats:
        CATEGORY_CODES.setdefault(_cat, set()).add(_eid)


class Skip(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _seconds(text: str | None, default: int) -> int:
    match = re.fullmatch(r"now-(\d+)([smhd])", (text or "").strip())
    if not match:
        return default
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def _channels(indexes: list[str]) -> set[str]:
    channels: set[str] = set()
    for index in indexes:
        target = WINDOWS_INDEXES.get(index)
        if target == "*":
            channels |= ALL_CHANNELS
        elif target:
            channels.add(target)
    return channels


def _filters(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Kibana filters -> extra conditions (only negated wildcard filters occur in the supplied rules)."""
    out = []
    for item in rule.get("filters") or []:
        query = item.get("query") or {}
        if list(query) != ["wildcard"]:
            raise Unsupported(f"Kibana filter type {list(query)} is not translated")
        (field, spec), = query["wildcard"].items()
        # Lucene wildcard escaping: backslash makes the next character literal.
        value = re.sub(r"\\(.)", r"\1", spec["value"])
        leaf = {"field": field, "op": "wildcard", "values": [value], "ci": bool(spec.get("case_insensitive"))}
        out.append({"not": leaf} if (item.get("meta") or {}).get("negate") else leaf)
    return out


def _with_category(condition: dict[str, Any], category: str | None) -> dict[str, Any]:
    """EQL '<category> where ...' is a test of event.category."""
    if not category or category == "any":
        return condition
    return {"all": [{"field": "event.category", "op": "eq", "values": [category]}, condition]}


def _codes(node: dict[str, Any]) -> set[int]:
    codes: set[int] = set()
    for name in ("event.code", "winlog.event_id"):
        values = conditions.literal_values(node, name)
        if values:
            codes |= {int(v) for v in values if str(v).isdigit()}
    return codes


def _action_sources(node: dict[str, Any]) -> list[tuple[str, int]]:
    values = conditions.literal_values(node, "event.action") or set()
    found: list[tuple[str, int]] = []
    for value in values:
        for item in ACTION_SOURCES.get(value, []) + ACTION_SOURCES_CI.get(str(value).casefold(), []):
            if item not in found:
                found.append(item)
    return found


def _neutralize_category(node: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Replace event.category tests with 'true' (used when an Event ID test already fixes the event type)."""
    changed = False

    def walk(item: dict[str, Any]) -> dict[str, Any]:
        nonlocal changed
        for key in ("all", "any"):
            if key in item:
                return {key: [walk(child) for child in item[key]]}
        if "not" in item:
            return {"not": walk(item["not"])}
        if item.get("field") == "event.category" and "fn" not in item:
            changed = True
            return {"const": True}
        return item
    return walk(node), changed


def _step_sources(node: dict[str, Any], category: str | None, channels: set[str], joins: list[str]) \
        -> tuple[list[dict[str, Any]], list[str]]:
    codes = _codes(node)
    candidates = av.candidate_sources(channels, None, codes)
    if not codes:
        for channel, eid in _action_sources(node):
            if channel in channels:
                candidates.append((f"generic:{channel}:{eid}", channel, eid))
    if not codes and not _action_sources(node) and schema.SECURITY in channels:
        categories = conditions.literal_values(node, "event.category") or set()
        inferred = sorted({eid for cat in categories for eid in CATEGORY_CODES.get(cat, set())})
        for eid in inferred:
            if eid not in (4688, 4689):
                candidates.append((f"generic:{schema.SECURITY}:{eid}", schema.SECURITY, eid))
    if category in ("any", "iam", "authentication", "configuration") and not codes and not _action_sources(node):
        specific = [c for c in candidates if not c[0].startswith("generic:")]
        if not specific:
            return [], ["no Event ID / action constraint: the rule would have to be evaluated against every event"]
        candidates = specific
    survivors = av.analyse(node, candidates, joins)
    if not survivors:
        reasons = av.rejected_reasons(node, candidates, joins) or ["no local Windows event source produces "
                                                                    "events matching the query's category/codes"]
        return [], reasons
    return survivors, []


def _tactic(rule: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    mitre = []
    tactic = None
    for threat in rule.get("threat") or []:
        name = (threat.get("tactic") or {}).get("name")
        tactic = tactic or name
        for technique in threat.get("technique") or []:
            entry = {"tactic": name or "", "technique": technique.get("id", ""), "name": technique.get("name", "")}
            mitre.append(entry)
            for sub in technique.get("subtechnique") or []:
                mitre.append({"tactic": name or "", "technique": sub.get("id", ""), "name": sub.get("name", "")})
        if not threat.get("technique") and name:
            mitre.append({"tactic": name, "technique": (threat.get("tactic") or {}).get("id", ""), "name": ""})
    return tactic or "Other", mitre


def _guide(note: str | None) -> str:
    if not note:
        return ""
    match = re.search(r"### Possible investigation steps\s*(.*?)(?:\n### |\Z)", note, re.S)
    text = (match.group(1) if match else note).strip()
    return text[:2500]


def _sources_summary(survivors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, set[int]] = {}
    for item in survivors:
        ids = [item["event_id"]] if item["event_id"] is not None else schema.SOURCES[item["key"]]["event_ids"]
        grouped.setdefault(item["channel"], set()).update(ids)
    return [{"channel": channel, "event_ids": sorted(ids)} for channel, ids in sorted(grouped.items())]


def _status(per_step: list[list[dict[str, Any]]]) -> tuple[str, str, list[str], list[str]]:
    """(status, confidence, optional sources, notes) from the surviving sources of every step."""
    notes: list[str] = []
    optional: set[str] = set()
    worst = "high"
    status = "fully_supported"
    for survivors in per_step:
        clean = [s for s in survivors if not s["lost_positive"] and not s["lost_exclusion"]]
        pool = clean or survivors
        if not clean:
            lost_pos = sorted({f for s in survivors for f in s["lost_positive"]})
            lost_exc = sorted({f for s in survivors for f in s["lost_exclusion"]})
            status = "partially_supported"
            if lost_exc:
                worst = "low"
                notes.append("Exclusion(s) on " + ", ".join(lost_exc) + " cannot be applied with local event data "
                             "(the detection may fire where the original would not).")
            if lost_pos:
                worst = "medium" if worst == "high" else worst
                notes.append("Condition branch(es) on " + ", ".join(lost_pos) + " cannot match with local event data "
                             "(narrower than the original).")
        mandatory = {s["channel"] for s in pool}
        if all(channel in av.OPTIONAL_CHANNELS for channel in mandatory):
            optional |= {av.OPTIONAL_CHANNELS[c] for c in mandatory}
        dc = [s for s in pool if s["event_id"] in av.DC_EVENTS]
        if dc and len(dc) == len(pool):
            optional.add("Domain controller role (these events are written only on domain controllers)")
        for s in pool:
            if s["event_id"] in av.REQUIRES_POLICY:
                notes.append(f"Event {s['event_id']} requires the audit policy: {av.REQUIRES_POLICY[s['event_id']]}.")
    if status == "fully_supported" and optional:
        status = "requires_optional_source"
    return status, worst, sorted(optional), sorted(set(notes))


def import_rule(path: Path) -> dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    rule, meta = data["rule"], data["metadata"]
    tactic, mitre = _tactic(rule)
    record: dict[str, Any] = {
        "source_file": path.name, "source_rule_id": rule["rule_id"], "name": rule["name"],
        "description": " ".join(rule.get("description", "").split()), "type": rule["type"],
        "language": rule.get("language"), "severity": SEVERITY.get(rule["severity"], "Medium"),
        "risk_score": int(rule["risk_score"]), "indexes": rule.get("index") or [], "license": rule.get("license"),
        "author": rule.get("author"), "tactic": tactic, "mitre": mitre, "tags": rule.get("tags") or [],
        "references": rule.get("references") or [], "false_positives": rule.get("false_positives") or [],
        "investigation": _guide(rule.get("note")), "maturity": meta.get("maturity"),
        "updated_date": meta.get("updated_date"), "query": rule.get("query", ""), "griffendo_id":
            "ELA-" + rule["rule_id"].replace("-", "")[:8].upper() + "-" + rule["rule_id"].replace("-", "")[-4:].upper(),
    }
    try:
        if rule["type"] == "esql":
            source = re.search(r"from\s+([^\n|]+)", rule.get("query", ""), re.I)
            local = source and any(w in source.group(1) for w in ("logs-windows", "winlogbeat", "logs-system"))
            if local:
                raise Skip("unsupported", "OUTSTANDING - ES|QL pipeline (STATS/EVAL/GROK) over Windows event logs: the data "
                                          "is local, so a port is possible, but ES|QL is not translated automatically and "
                                          "this rule has not been ported by hand yet")
            raise Skip("unsupported", "ES|QL query over non-Windows-event-log data (EDR / alert indexes)")
        if rule["type"] == "machine_learning":
            raise Skip("unsupported", "Elastic machine-learning job")
        indexes = rule.get("index") or []
        channels = _channels(indexes)
        if not channels:
            edr = [i for i in indexes if i.startswith(EDR_INDEXES)]
            raise Skip("unsupported", "Requires " + (", ".join(sorted({_edr_name(i) for i in edr})) or
                                                     "non-Windows-event-log data") + " telemetry; the rule declares no "
                                                                                     "Windows Event Log data source")
        modifications: list[str] = []
        joins: list[str] = []
        if rule["language"] == "eql":
            parsed = eql.parse(rule["query"])
            steps = []
            for step in parsed.steps:
                condition = _with_category(eql.translate_expr(step.expr), step.category)
                steps.append({"category": step.category, "condition": condition,
                              "by": [f for f in (step.by or parsed.by) if f not in HOST_FIELDS], "runs": step.runs})
            joins_all = [f for f in parsed.by if f not in HOST_FIELDS]
            if any(f in HOST_FIELDS for f in parsed.by) or any(f in HOST_FIELDS for s in parsed.steps for f in s.by):
                modifications.append("Sequence join on the host (host.id / host.name / winlog.computer_name) is "
                                     "implicit: Griffendo correlates events of one host.")
            until = None
            if parsed.until:
                until = {"category": parsed.until.category,
                         "condition": _with_category(eql.translate_expr(parsed.until.expr), parsed.until.category),
                         "by": [f for f in (parsed.until.by or parsed.by) if f not in HOST_FIELDS]}
            kind = "sequence" if parsed.kind == "sequence" else "single"
            maxspan = parsed.maxspan
        else:
            condition = kql.parse(rule["query"])
            steps = [{"category": None, "condition": condition, "by": [], "runs": 1}]
            kind = {"query": "single", "threshold": "threshold", "new_terms": "new_terms"}[rule["type"]]
            maxspan, until, joins_all = None, None, []
        extra = _filters(rule)
        if extra:
            steps[0]["condition"] = {"all": [steps[0]["condition"], *extra]}
            modifications.append(f"{len(extra)} Kibana filter(s) folded into the condition.")
        per_step = []
        reasons: list[str] = []
        for step in steps:
            if _codes(step["condition"]) or _action_sources(step["condition"]):
                step["condition"], changed = _neutralize_category(step["condition"])
                if changed and "category-neutralized" not in modifications:
                    modifications.append("category-neutralized")
            joins = step["by"]
            problems = conditions.validate(step["condition"])
            if problems:
                raise Unsupported("; ".join(problems[:3]))
            survivors, why = _step_sources(step["condition"], step["category"], channels, joins)
            if not survivors:
                reasons.extend(why)
                break
            step["sources"] = _sources_summary(survivors)
            step["survivors"] = survivors
            per_step.append(survivors)
        if reasons or len(per_step) != len(steps):
            raise Skip("unsupported", "; ".join(sorted(set(reasons)))[:600])
        if "category-neutralized" in modifications:
            modifications.remove("category-neutralized")
            modifications.append("event.category tests dropped where the rule already tests the Event ID/action "
                                 "(Griffendo does not reproduce Elastic's categorisation of every Windows event).")
        status, confidence, optional, notes = _status(per_step)
        extra_spec: dict[str, Any] = {}
        if kind == "threshold":
            threshold = rule["threshold"]
            by = [f for f in threshold.get("field", []) if f not in HOST_FIELDS]
            if any(f in HOST_FIELDS for f in threshold.get("field", [])):
                modifications.append("Threshold grouping on host.id is implicit (single host).")
            if threshold.get("cardinality"):
                raise Skip("unsupported", "Threshold cardinality condition is not translated")
            window = _seconds(rule.get("from"), 360)
            extra_spec["threshold"] = {"by": by, "count": int(threshold["value"]), "window_seconds": window}
            modifications.append(f"Threshold evaluated over a sliding {window // 60}-minute window "
                                 f"(the rule's look-back 'from = {rule.get('from')}').")
            for name in by:
                if not all(av.Analysis(s["key"], s["channel"], s["event_id"]).available(name) for s in per_step[0]):
                    raise Skip("unsupported", f"Threshold group field {name} is not available from local events")
        if kind == "new_terms":
            fields = [f for f in rule["new_terms"]["value"] if f not in HOST_FIELDS]
            history = "now-7d"
            for item in rule["new_terms"].get("history_window_start") or []:
                history = item.get("value", history)
            days = max(1, _seconds(history, 7 * 86400) // 86400)
            if any(f in HOST_FIELDS for f in rule["new_terms"]["value"]):
                modifications.append("New-terms combination includes host.id implicitly (single host).")
            if not fields:
                modifications.append("New-terms on host only: the detection fires the first time the query matches "
                                     "on this host within the history window.")
            for name in fields:
                usable = [s for s in per_step[0] if av.Analysis(s["key"], s["channel"], s["event_id"]).available(name)]
                if not usable:
                    raise Skip("unsupported", f"New-terms field {name} is not available from local events")
            extra_spec["new_terms"] = {"fields": fields, "history_days": days}
        witnesses = []
        for step in steps:
            found = None
            for survivor in step["survivors"]:
                found = av.witness_event(step["condition"], survivor["key"], survivor["channel"], survivor["event_id"])
                if found:
                    break
            witnesses.append(found is not None)
        record.update(status=status, reason="; ".join(notes), confidence=confidence, optional_sources=optional,
                      kind=kind, steps=[{k: v for k, v in s.items() if k != "survivors"} for s in steps],
                      maxspan=maxspan, until=until, joins=joins_all, modifications=modifications,
                      witness=all(witnesses), **extra_spec)
    except Skip as skip:
        record.update(status=skip.status, reason=skip.reason)
    except Unsupported as error:
        record.update(status="unsupported", reason=f"Not translatable: {error}")
    return record


def _edr_name(index: str) -> str:
    for prefix, name in (("logs-endpoint.", "Elastic Defend"), ("endgame-", "Elastic Endgame"),
                         ("logs-sentinel_one", "SentinelOne"), ("logs-crowdstrike", "CrowdStrike"),
                         ("logs-m365_defender", "Microsoft 365 Defender"), (".alerts-", "Elastic alert index"),
                         ("logs-microsoft_defender", "Microsoft Defender for Endpoint")):
        if index.startswith(prefix):
            return name
    return index


def import_all(folder: Path) -> list[dict[str, Any]]:
    return [import_rule(path) for path in sorted(folder.glob("*.toml"))]
