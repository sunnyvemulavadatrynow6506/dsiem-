"""Chain correlator: multi-event chains joined through process lineage, logon sessions or field values.

A chain rule lists ordered steps.  Each step has a condition and (except the first)
a relation to an earlier step:

    child_of / descendant_of     the step's process was created by / descends from the earlier step's process
    process_or_descendant        the step's acting process is that process or one of its descendants
    same_logon / same_user       same (non-system) logon session / account ("only_without_process": only for
                                 events that carry no process identity, such as Security 4698)
    field_equals                 a field of this event equals a field of the earlier event ({"field", "other"})
    {"any": [relation, ...]}     any of several relations

Process relationships come from the State Manager's process table (Sysmon ProcessGuid,
or PID + creation time from Security 4688), never from PIDs alone and never from
time proximity alone: events that are merely close in time are not joined.  Every
step must fall inside the rule's window, in time order.  The evidence (events, the
relation used for each link) is stored with the signal.
"""
from __future__ import annotations

from typing import Any

from .matcher import draft
from .normalizer import get
from .state import StateManager

MAX_CANDIDATES = 40


class ChainCorrelator:
    def __init__(self, state: StateManager):
        self.state = state

    def evaluate(self, rule, ev: dict[str, Any], t: float, process_key: str | None) -> list[dict[str, Any]]:
        spec = rule.spec["chain"]
        window = float(spec.get("window_seconds", 600))
        family = self.state.family(f"chain:{rule.id}:{rule.rev}", window * 2)
        hits = [index for index, step in enumerate(rule.steps) if step["predicate"](ev)]
        if not hits:
            return []
        record = {"t": t, "ev": ev, "process": process_key, "logon": _logon(ev), "user": _user(ev)}
        for index in hits:
            family.add(index, t, record)
        for index in hits:
            chain = self._assemble(rule, family, index, record, window)
            if chain:
                events = [item["ev"] for item in chain]
                links = []
                for position, item in enumerate(chain):
                    relation = rule.steps[position]["relation"]
                    links.append({"step": rule.steps[position]["name"], "time": item["ev"]["@timestamp"],
                                  "event_id": item["ev"].get("event.code"), "channel": item["ev"].get("winlog.channel"),
                                  "process": item["ev"].get("process.name"), "relation": _relation_label(relation),
                                  "via": item.get("via")})
                return [draft(rule, events, source="chain", details={"chain": links, "window_seconds": int(window)})]
        return []

    def _assemble(self, rule, family, fixed: int, record: dict[str, Any], window: float):
        steps = rule.steps
        chain: list[dict[str, Any] | None] = [None] * len(steps)
        chain[fixed] = dict(record)
        t = record["t"]

        def candidates(index: int) -> list[dict[str, Any]]:
            w = family.get(index)
            if w is None:
                return []
            items = [dict(item) for _, item in w.between(t - window, t + window)]
            return items[-MAX_CANDIDATES:]

        def search(position: int) -> bool:
            if position == len(steps):
                times = [item["t"] for item in chain]
                return max(times) - min(times) <= window
            if position == fixed:
                via = self._related(steps[position]["relation"], chain, position)
                if steps[position]["relation"] and via is None:
                    return False
                chain[position]["via"] = via
                return search(position + 1)
            for item in reversed(candidates(position)):
                if any(other is not None and other["ev"]["_key"] == item["ev"]["_key"] for other in chain):
                    continue
                previous = [chain[i]["t"] for i in range(position) if chain[i] is not None]
                later = [chain[i]["t"] for i in range(position + 1, len(steps)) if chain[i] is not None]
                if previous and item["t"] < max(previous):
                    continue
                if later and item["t"] > min(later):
                    continue
                chain[position] = item
                via = self._related(steps[position]["relation"], chain, position)
                if steps[position]["relation"] and via is None:
                    chain[position] = None
                    continue
                item["via"] = via
                if search(position + 1):
                    return True
                chain[position] = None
            return False

        # Positions before the fixed one are filled first (their relations only point backwards).
        if search(0):
            return chain
        return None

    def _related(self, relation: Any, chain: list, position: int) -> str | None:
        if not relation:
            return "start"
        if "any" in relation:
            for option in relation["any"]:
                via = self._related(option, chain, position)
                if via:
                    return via
            return None
        target = chain[relation["step"]]
        current = chain[position]
        if target is None or current is None:
            return None
        kind = relation["type"]
        if relation.get("only_without_process") and current["process"]:
            # e.g. a 4698 task registration carries no process: only then is the logon session the link.
            return None
        processes = self.state.processes
        if kind in ("child_of", "descendant_of", "process_or_descendant"):
            mine, theirs = current["process"], target["process"]
            if not mine or not theirs:
                return None
            if kind == "process_or_descendant" and mine == theirs:
                return "same process"
            ancestors = processes.ancestors(mine, depth=int(relation.get("max_depth", 6)))
            if kind == "child_of":
                return "child process" if ancestors[:1] == [theirs] else None
            if theirs in ancestors:
                depth = ancestors.index(theirs) + 1
                return "child process" if depth == 1 else f"descendant (depth {depth})"
            return None
        if kind == "same_logon":
            if current["logon"] and current["logon"] == target["logon"]:
                return f"same logon session {current['logon']}"
            return None
        if kind == "same_user":
            if current["user"] and current["user"] == target["user"]:
                return f"same user {current['user']}"
            return None
        if kind == "field_equals":
            mine = get(current["ev"], relation["field"])
            theirs = get(target["ev"], relation["other"])
            if mine is None or theirs is None:
                return None
            a, b = str(mine), str(theirs)
            if relation.get("ci", True):
                a, b = a.casefold().strip('"'), b.casefold().strip('"')
            return f"{relation['field']} = {relation['other']}" if a == b else None
        return None


def _logon(ev: dict[str, Any]) -> str | None:
    from .schema import SYSTEM_LOGON_IDS
    logon = ev.get("winlog.logon.id")
    if isinstance(logon, str) and logon.lower() not in SYSTEM_LOGON_IDS:
        return logon.lower()
    return None


def _user(ev: dict[str, Any]) -> str | None:
    from .normalizer import entity
    return entity(ev).get("user")


def _relation_label(relation: Any) -> str | None:
    if not relation:
        return None
    if "any" in relation:
        return " or ".join(filter(None, (_relation_label(item) for item in relation["any"])))
    return relation["type"].replace("_", " ") + f" step {relation['step'] + 1}"
