"""Rule inventory, one-file-per-rule layout, and translated rules firing on generated positive events."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "rules_import"))
RULES = ROOT / "src" / "logplatform" / "detection" / "rules"
INVENTORY = json.loads((ROOT / "docs" / "rules_inventory.json").read_text(encoding="utf-8"))
RESULTS = ROOT / "docs" / "perf" / "v5_rule_witness_results.json"


@pytest.fixture(scope="module")
def registry():
    from logplatform.detection.engine.registry import Registry
    from logplatform.detection.rules import load_all
    rules, errors = load_all()
    assert errors == []
    return Registry(rules)


def test_every_rule_has_its_own_file_and_is_indexed(registry):
    from logplatform.detection.rules.index import MODULES
    files = sorted(RULES.rglob("rule_*.py"))
    assert len(files) == len(MODULES) == len(registry.rules) == len(set(MODULES))
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert text.count("\nRULE = ") == 1, path                     # exactly one rule per file
    big = [p for p in (RULES.parent / "engine").glob("*.py") if "RULE = {" in p.read_text(encoding="utf-8")]
    assert not big                                                     # no rule logic inside engine files


def test_every_rule_folder_is_a_regular_package():
    # PyInstaller's frozen importer does not support namespace packages: a folder without
    # __init__.py imports from source but not from the exe.
    for folder in [RULES, *(p for p in RULES.rglob("*") if p.is_dir() and p.name != "__pycache__")]:
        assert (folder / "__init__.py").exists(), folder


def test_inventory_covers_every_supplied_rule():
    elastic = [e for e in INVENTORY if e["source"] == "Elastic"]
    wazuh = [e for e in INVENTORY if e["source"] == "Wazuh"]
    assert len(elastic) == 499 and len(wazuh) == 946
    for entry in elastic + wazuh:
        assert entry["status"] in ("fully_supported", "partially_supported", "requires_optional_source", "unsupported")
        assert entry["license"]
        if entry["status"] == "unsupported":
            assert entry["reason"] and not entry.get("module")       # excluded, with a reason
        else:
            assert entry["module"] and entry["griffendo_id"]


def test_unsupported_rules_are_not_loaded(registry):
    excluded = {e["source_rule_id"] for e in INVENTORY if e["status"] == "unsupported"}
    loaded_sources = {(r.spec.get("source") or {}).get("rule_id") for r in registry.rules.values()}
    assert not excluded & loaded_sources


def test_provenance_and_licence_kept_per_rule(registry):
    for rule in registry.rules.values():
        source = rule.spec.get("source") or {}
        assert source.get("platform") and source.get("license"), rule.id
        if rule.origin == "elastic":
            assert source["license"] == "Elastic License v2" and source["original_query"] and source["rule_id"]
        if rule.origin == "wazuh":
            assert source["license"].startswith("GPL-2.0") and "Wazuh" in source["attribution"]


def test_no_normalized_field_is_invented_for_edr_only_names():
    from logplatform.detection.engine import schema
    produced = set().union(*(s["fields"] for s in schema.SOURCES.values()))
    edr = [f for f in produced if f.startswith(("process.Ext.", "process.code_signature.", "process.thread."))]
    assert edr == []


def _now(offset: float = 0) -> tuple[str, float]:
    when = datetime.now(timezone.utc) - timedelta(hours=1) + timedelta(seconds=offset)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), when.timestamp()


def _engine():
    from logplatform.detection.engine.matcher import Matcher
    from logplatform.detection.engine.model_store import ModelStore, TermStore
    from logplatform.detection.engine.state import StateManager
    state = StateManager()
    return Matcher(state, TermStore(ModelStore(None), lambda since: True)), state


def _witness(condition, source):
    import availability as av
    from logplatform.detection.engine import schema
    for eid in source.get("event_ids") or [None]:
        key = schema.source_key(source["channel"], eid)
        if eid is None and key.startswith("generic:"):
            continue
        event = av.witness_event(condition, key, source["channel"], eid)
        if event is not None:
            return event
    return None


def _fire(rule) -> str:
    matcher, _ = _engine()
    spec = rule.spec
    counter = [0]

    def stamp(event, offset):
        counter[0] += 1
        event = dict(event, _key=f"w{counter[0]}")
        event["@timestamp"], t = _now(offset)
        return event, t

    if rule.kind in ("single", "new_terms", "threshold"):
        base = next((w for w in (_witness(spec["condition"], s) for s in spec["sources"]) if w), None)
        if base is None:
            return "no witness"
        count = spec["threshold"]["count"] if rule.kind == "threshold" else 1
        for field in (spec.get("new_terms") or {}).get("fields") or []:
            if field.startswith("winlog.event_data."):
                if field[18:].lower() not in base["_lower"]:
                    base = dict(base, _lower={**base["_lower"], field[18:].lower(): "synthetic-term"})
            elif field not in base:
                base = dict(base, **{field: "synthetic-term"})
        signals = []
        for i in range(count):
            event, t = stamp(base, i)
            signals += matcher.evaluate(rule, event, t)
        return "fired" if signals else "missed"
    if rule.kind == "sequence":
        events = []
        for index, step in enumerate(spec["steps"]):
            base = next((w for w in (_witness(step["condition"], s) for s in step["sources"]) if w), None)
            if base is None:
                return "no witness"
            events.append((base, step.get("by") or [], int(step.get("runs", 1))))
        from logplatform.detection.engine.normalizer import get
        first_base, first_by, _ = events[0]
        join = [get(first_base, field) or f"synthetic-join-{i}" for i, field in enumerate(first_by)]
        signals, offset = [], 0
        for base, by, runs in events:
            for _ in range(runs):
                event, t = stamp(base, offset)
                for position, field in enumerate(by):      # steps may join on different fields (EQL "by" per step)
                    value = join[position] if position < len(join) else "synthetic-join"
                    if field.startswith("winlog.event_data."):
                        event["_lower"] = {**event["_lower"], field[18:].lower(): value}
                    else:
                        event[field] = value
                offset += 0.2                              # well inside the shortest maxspan (1 s)
                signals += matcher.evaluate(rule, event, t)
        return "fired" if signals else "missed"
    return "skipped"


def test_translated_elastic_and_griffendo_rules_fire_on_generated_events(registry):
    outcomes: dict[str, list[str]] = {}
    for rule in registry.rules.values():
        if rule.origin not in ("elastic", "griffendo", "catalog") or rule.kind not in ("single", "new_terms", "threshold",
                                                                                     "sequence"):
            continue
        outcomes.setdefault(_fire(rule), []).append(rule.id)
    summary = {key: len(value) for key, value in outcomes.items()}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    previous = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    previous["deterministic"] = {"counts": summary, "missed": outcomes.get("missed", []),
                                 "no_witness": outcomes.get("no witness", [])}
    RESULTS.write_text(json.dumps(previous, indent=1))
    assert outcomes.get("missed", []) == []                # every rule with a positive example fires
    assert summary["fired"] >= 500


def test_wazuh_rules_fire_through_the_rule_tree(registry):
    import availability as av
    from logplatform.detection.engine.matcher import WazuhTree
    from logplatform.detection.engine.model_store import ModelStore, TermStore
    from logplatform.detection.engine.state import StateManager
    from logplatform.detection.engine import schema

    by_wazuh = {r.spec["wazuh"]["wazuh_id"]: r for r in registry.wazuh}
    parents = {}
    for rule in registry.wazuh:
        w = rule.spec["wazuh"]
        parents[rule.id] = [by_wazuh[p] for p in (w["if_sid"] + w["if_matched_sid"]) if p in by_wazuh]
    outcomes: dict[str, list[str]] = {}
    for rule in registry.wazuh:
        w = rule.spec["wazuh"]
        if not rule.alerting or w.get("if_group") or w.get("if_matched_group") or w.get("if_fts"):
            continue
        path, node = [rule], rule
        while parents.get(node.id):
            node = parents[node.id][0]
            path.insert(0, node)
        flat = {"all": [p.spec["wazuh"]["condition"] for p in path]}
        channels = w.get("channels") or ["Microsoft-Windows-TaskScheduler/Operational", "Application"]
        codes = [int(c) for c in rule.spec["sources"][0]["event_ids"]] if rule.spec["sources"] and \
            rule.spec["sources"][0]["event_ids"] else [None]
        event = None
        for channel in channels:
            for code in codes:
                key = schema.source_key(channel, code) if code is not None else f"generic:{channel}:0"
                event = av.witness_event(flat, key, channel, code)
                if event:
                    break
            if event:
                break
        if event is None:
            outcomes.setdefault("no witness", []).append(rule.id)
            continue
        tree = WazuhTree(registry.wazuh, StateManager(), TermStore(ModelStore(None), lambda since: True))
        signals = []
        for i in range(int(w.get("frequency") or 1)):
            item = dict(event, _key=f"wz{i}")
            item["@timestamp"], t = _now(i)
            signals = tree.evaluate(item, t)
        if not signals:
            outcomes.setdefault("missed", []).append(rule.id)
            continue
        final = signals[0]["rule_id"]
        route = [step["id"] for step in signals[0]["details"]["wazuh_path"]]
        if final == rule.id or w["wazuh_id"] in route:
            outcomes.setdefault("fired", []).append(rule.id)
        else:
            # Wazuh evaluates siblings in order and the first match wins: an earlier sibling took the event.
            outcomes.setdefault("taken by an earlier sibling", []).append(f"{rule.id}->{final}")
    summary = {key: len(value) for key, value in outcomes.items()}
    previous = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    previous["wazuh"] = {"counts": summary, "missed": outcomes.get("missed", []),
                         "taken_by_sibling": outcomes.get("taken by an earlier sibling", []),
                         "no_witness": outcomes.get("no witness", [])}
    RESULTS.write_text(json.dumps(previous, indent=1))
    assert outcomes.get("missed", []) == []
    assert summary["fired"] >= 700


def test_rule_ids_are_stable_and_well_formed(registry):
    for rule_id in registry.rules:
        assert re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{2,63}$", rule_id)
