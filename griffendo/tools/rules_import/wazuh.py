"""Inspect, classify and translate the Wazuh Windows rules (New folder.zip, XML)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import availability as av

from logplatform.detection.engine import conditions, schema

FIELD_MAP = {
    "win.system.eventid": "event.code", "win.system.providername": "event.provider",
    "win.system.channel": "winlog.channel", "win.system.severityvalue": "griffendo.severity_value",
    "win.system.computer": "winlog.computer_name", "win.system.eventrecordid": "winlog.record_id",
    "win.system.processid": "winlog.process.pid", "win.system.threadid": "winlog.process.thread.id",
    "win.system.keywords": "winlog.keywords", "win.system.task": "winlog.task", "win.system.opcode": "winlog.opcode",
    "win.system.message": "message", "win.system.level": "griffendo.level_code",
}
# Wazuh level -> Griffendo severity (Wazuh: 0 ignored ... 15 severe attack; alerts start at level 3).
LEVEL_SEVERITY = [(13, "Critical"), (10, "High"), (7, "Medium"), (4, "Low"), (3, "Informational")]
ALERT_LEVEL = 3
BUILTIN_PROVIDER_PREFIXES = ("Microsoft-Windows-", "Microsoft-Windows ", "Service Control Manager", "Eventlog",
                             "EventLog", "Application Error", "Application Hang", "Windows Error Reporting",
                             "MsiInstaller", "Microsoft-Windows-Security-Auditing", "Microsoft Windows",
                             "Microsoft Office", "Microsoft-Antimalware", "SceCli", "Userenv", "Winlogon", "Wininit",
                             "Disk", "Ntfs", "volsnap", "VSS", "ESENT", "SecurityCenter", "User32", "Kernel-",
                             "Microsoft-Windows-Kernel", "Tcpip", "Dhcp", "LsaSrv", "NETLOGON", "W32Time", "TermDD",
                             "Schannel", "SideBySide", "WinMgmt", "Wlclntfy", "Software Protection Platform Service",
                             "SecurityCenter", "WMI", "Windows Defender", "Microsoft Antimalware", "WinRM")
# Third-party / legacy products whose events only exist when the product is installed.  Every other
# provider named by the supplied rules is a built-in Windows component.
OPTIONAL_PRODUCTS = {"McLogEvent": "McAfee VirusScan", "Microsoft Antimalware": "Microsoft Security Essentials / "
                     "System Center Endpoint Protection", "chromoting": "Chrome Remote Desktop"}


def severity_for(level: int) -> str | None:
    for minimum, name in LEVEL_SEVERITY:
        if level >= minimum:
            return name
    return None


def risk_for(severity: str | None) -> int:
    return {"Critical": 95, "High": 75, "Medium": 50, "Low": 30, "Informational": 10}.get(severity or "", 0)


# ------------------------------------------------------------------------------------------- OS_Regex
_CLASSES = {"w": r"[A-Za-z0-9\-@_]", "d": r"[0-9]", "s": r"[ ]", "t": r"\t",
            "p": r"""[()*+,\-.:;<=>?\[\]!"'#$%&|{}]""", "W": r"[^A-Za-z0-9\-@_]", "D": r"[^0-9]", "S": r"[^ ]",
            ".": r"."}


def _split_alternatives(pattern: str) -> list[str]:
    parts, current, i = [], [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            current.append(pattern[i:i + 2])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def clean_pattern(pattern: str) -> str:
    """Patterns wrapped over several XML lines: the line break and indentation are layout, not pattern."""
    return re.sub(r"\s*\n\s*", "", pattern)


def osregex_to_python(pattern: str) -> tuple[str, list[str] | None]:
    """OS_Regex (Wazuh default for <field>) -> (Python regex with search semantics, exact literals or None).

    OS_Regex: case-insensitive; ``\\w \\d \\s \\t \\p \\W \\D \\S`` classes, ``\\.`` any character,
    ``+``/``*`` repeat the previous token, ``^``/``$`` anchors, ``|`` alternatives, other escapes literal,
    unescaped parentheses group.  Literals are returned when every alternative is ``^literal$``.
    """
    alternatives = []
    literals: list[str] | None = []
    # Empty alternatives come from patterns wrapped over lines ("...^4735$|<newline>|^641$..."): they are
    # layout, not "match anything", so they are dropped.
    for alt in [a for a in _split_alternatives(pattern) if a != ""] or [""]:
        anchored_start = alt.startswith("^")
        body = alt[1:] if anchored_start else alt
        anchored_end = body.endswith("$") and not body.endswith("\\$")
        body = body[:-1] if anchored_end else body
        out, literal_text, is_literal = [], [], True
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in _CLASSES:
                    out.append(_CLASSES[nxt])
                    is_literal = False
                else:
                    out.append(re.escape(nxt))
                    literal_text.append(nxt)
                i += 2
                continue
            if ch in "+*":
                out.append(ch)
                is_literal = False
            elif ch == "(":
                out.append("(?:")
                is_literal = False
            elif ch == ")":
                out.append(")")
                is_literal = False
            else:
                out.append(re.escape(ch))
                literal_text.append(ch)
            i += 1
        regex = ("" if anchored_start else ".*") + "".join(out) + ("" if anchored_end else ".*")
        alternatives.append(regex)
        if literals is not None and anchored_start and anchored_end and is_literal:
            literals.append("".join(literal_text))
        else:
            literals = None
    return "|".join(f"(?:{alt})" for alt in alternatives), literals


def field_condition(name: str, pattern: str, negate: bool) -> dict[str, Any]:
    lname = name.lower()
    if lname in FIELD_MAP:
        target = FIELD_MAP[lname]
    elif lname.startswith("win.eventdata."):
        target = "winlog.event_data." + name.split(".", 2)[2]
    else:
        target = "wazuh." + name
    regex, literals = osregex_to_python(clean_pattern(pattern))
    if literals is not None:
        leaf = {"field": target, "op": "eq", "values": literals, "ci": True}
    else:
        leaf = {"field": target, "op": "regex", "values": [regex], "ci": True}
    return {"not": leaf} if negate else leaf


# ------------------------------------------------------------------------------------------- parsing
def _load(folder: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    variables: dict[str, str] = {}
    texts = []
    for path in sorted(folder.glob("*.xml")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'<var name="(\w+)">([^<]*)</var>', text):
            variables[match.group(1)] = match.group(2)
        texts.append((path, text))
    rules = []
    order = 0
    for path, text in texts:
        header = re.search(r"<!--(.*?)-->", text, re.S)
        cleaned = re.sub(r'<var name="(\w+)">([^<]*)</var>', "", text)
        cleaned = re.sub(r"<\?xml[^>]*\?>", "", cleaned)
        for name, value in sorted(variables.items(), key=lambda item: -len(item[0])):
            cleaned = cleaned.replace("$" + name, value)
        root = ET.fromstring("<root>" + cleaned + "</root>")
        for group in root.iter("group"):
            group_names = [g for g in (group.get("name") or "").split(",") if g]
            for element in group.findall("rule"):
                order += 1
                rules.append(_rule(element, path.name, group_names, order,
                                   " ".join((header.group(1) if header else "").split())))
    return rules, variables


def _ids(text: str | None) -> list[str]:
    return [item for item in re.split(r"[\s,]+", text or "") if item]


def _rule(element: ET.Element, filename: str, group_names: list[str], order: int, header: str) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "wazuh_id": element.get("id"), "level": int(element.get("level")), "source_file": filename,
        "order": order, "frequency": int(element.get("frequency")) if element.get("frequency") else None,
        "timeframe": int(element.get("timeframe")) if element.get("timeframe") else None,
        "if_sid": [], "if_group": [], "if_matched_sid": [], "if_matched_group": [], "same_field": [],
        "different_field": [], "fields": [], "groups": list(group_names), "mitre": [], "description": "",
        "unsupported": [], "license_header": header, "options": [],
    }
    for child in element:
        tag = child.tag
        text = (child.text or "").strip()
        if tag == "if_sid":
            rule["if_sid"] += _ids(text)
        elif tag == "if_group":
            rule["if_group"] += _ids(text)
        elif tag == "if_matched_sid":
            rule["if_matched_sid"] += _ids(text)
        elif tag == "if_matched_group":
            rule["if_matched_group"] += _ids(text)
        elif tag == "same_field":
            rule["same_field"].append(text)
        elif tag == "different_field":
            rule["different_field"].append(text)
        elif tag == "field":
            if child.get("type") not in (None, "osregex"):
                rule["unsupported"].append(f"field type {child.get('type')}")
            rule["fields"].append((child.get("name"), text, child.get("negate") == "yes"))
        elif tag == "description":
            rule["description"] = " ".join(text.split())
        elif tag == "group":
            rule["groups"] += [g for g in text.split(",") if g]
        elif tag == "mitre":
            rule["mitre"] += [(item.text or "").strip() for item in child.findall("id")]
        elif tag == "options":
            rule["options"].append(text)
        elif tag == "if_fts":
            rule["if_fts"] = True
        elif tag == "match":
            rule["unsupported"].append("<match> on the full log text (Griffendo keeps structured fields, not the "
                                       "Wazuh JSON log line)")
        elif tag == "regex":
            rule["unsupported"].append("<regex> on the full log text")
        elif tag == "decoded_as":
            rule["decoded_as"] = text
        elif tag in ("category", "info"):
            continue
        else:
            rule["unsupported"].append(f"<{tag}>")
    return rule


# ------------------------------------------------------------------------------------------- classification
def import_all(folder: Path) -> list[dict[str, Any]]:
    rules, _ = _load(folder)
    by_id = {rule["wazuh_id"]: rule for rule in rules}
    group_members: dict[str, list[str]] = {}
    for rule in rules:
        for group in rule["groups"]:
            group_members.setdefault(group, []).append(rule["wazuh_id"])
    for rule in rules:
        rule["griffendo_id"] = f"WAZ-{rule['wazuh_id']}"
        rule["condition"] = {"all": [field_condition(n, p, neg) for n, p, neg in rule["fields"]]} \
            if rule["fields"] else {"const": True}
        rule["severity"] = severity_for(rule["level"])
        rule["risk_score"] = risk_for(rule["severity"])
        rule["alerting"] = rule["level"] >= ALERT_LEVEL
        missing = [p for p in rule["if_sid"] + rule["if_matched_sid"] if p not in by_id]
        missing_groups = [g for g in rule["if_group"] + rule["if_matched_group"] if g not in group_members]
        if missing:
            rule["unsupported"].append("parent rule(s) " + ", ".join(missing) + " are not in the supplied files")
        if missing_groups:
            rule["unsupported"].append("parent group(s) " + ", ".join(missing_groups) + " have no member rules")

    def chains(rule: dict[str, Any], depth: int = 0) -> list[list[dict[str, Any]]]:
        """Every ancestor path (root first) for a rule."""
        if depth > 30:
            return []
        parents = [by_id[p] for p in rule["if_sid"] + rule["if_matched_sid"] if p in by_id]
        for group in rule["if_group"] + rule["if_matched_group"]:
            parents += [by_id[p] for p in group_members.get(group, []) if p != rule["wazuh_id"]]
        if not parents:
            return [[rule]]
        out = []
        for parent in parents:
            for path in chains(parent, depth + 1):
                out.append(path + [rule])
                if len(out) > 40:
                    return out
        return out

    for rule in rules:
        rule["paths"] = chains(rule)
        problems = list(rule["unsupported"])
        for path in rule["paths"]:
            for ancestor in path[:-1]:
                problems += [f"ancestor {ancestor['wazuh_id']}: {p}" for p in ancestor["unsupported"]]
        survivors_all = []
        lost_pos, lost_exc = set(), set()
        channels: set[str] = set()
        providers: set[str] = set()
        witness_ok = False
        for path in rule["paths"]:
            flat = {"all": [node["condition"] for node in path]}
            channel_values = conditions.literal_values(flat, "winlog.channel") or set()
            provider_values = conditions.literal_values(flat, "event.provider") or set()
            codes = conditions.literal_values(flat, "event.code") or set()
            targets = [c for c in channel_values] or ["security", "system", "application",
                                                        schema.TASKS.lower()]
            candidates = []
            for channel in targets:
                proper = next((c for c in [schema.SECURITY, schema.SYSTEM, schema.APPLICATION, schema.SYSMON,
                                           schema.DEFENDER, schema.FIREWALL, schema.POWERSHELL]
                               if c.lower() == channel), channel)
                if codes:
                    for code in sorted(codes, key=lambda c: int(c) if c.isdigit() else 0):
                        if code.isdigit():
                            key = schema.source_key(proper, int(code))
                            candidates.append((key, proper, int(code)))
                else:
                    candidates.append((f"generic:{proper}:0", proper, None))
            survivors = []
            for key, channel, eid in candidates:
                analysis = av.Analysis(key, channel, eid)
                if eid is None:
                    analysis.consts.pop("event.code", None)
                    analysis.consts.pop("winlog.event_id", None)
                    analysis.consts.pop("event.action", None)
                    analysis.consts.pop("event.category", None)
                    analysis.consts.pop("event.type", None)
                verdict = analysis.run(flat)
                lost_pos |= analysis.lost_positive
                lost_exc |= analysis.lost_exclusion
                if verdict != av.F:
                    survivors.append((key, channel, eid))
                    channels.add(channel)
                    if not witness_ok and _witness(flat, key, channel, eid):
                        witness_ok = True
            survivors_all += survivors
            providers |= provider_values
        def original_channels(node):
            found = []
            if isinstance(node, dict):
                if node.get("field") == "winlog.channel" and node.get("op") == "eq":
                    found += node["values"]
                for key in ("all", "any"):
                    for child in node.get(key, []):
                        found += original_channels(child)
            return found
        case_map = {c.lower(): c for path in rule["paths"] for n in path for c in original_channels(n["condition"])}
        channels = {case_map.get(c.lower(), c) for c in channels}
        any_channel = any(not (conditions.literal_values({"all": [n["condition"] for n in path]}, "winlog.channel"))
                          for path in rule["paths"])
        rule["channels"] = [] if any_channel else sorted(channels)
        rule["providers"] = sorted(providers)
        rule["witness"] = witness_ok
        rule["event_codes"] = sorted({c for path in rule["paths"] for c in
                                      (conditions.literal_values({"all": [n["condition"] for n in path]}, "event.code")
                                       or set())}, key=lambda c: int(c) if c.isdigit() else 0)
        notes = []
        optional = []
        top_level = not (rule["if_sid"] or rule["if_matched_sid"] or rule["if_group"] or rule["if_matched_group"])
        if top_level and rule.get("decoded_as") != "windows_eventchannel" and rule["wazuh_id"] != "60000":
            problems.append("Top-level rule without the windows_eventchannel decoder: in Wazuh's rule order rule 60000 "
                            "matches every Windows event-channel event first, so this rule is never reached for them")
        if problems:
            rule["status"], rule["reason"] = "unsupported", "; ".join(sorted(set(problems)))
        elif not survivors_all:
            reason = ", ".join(sorted(lost_pos)) or "conditions"
            rule["status"] = "unsupported"
            rule["reason"] = (f"needs {reason}, which Griffendo does not collect (Windows renders the message text "
                              f"from the provider's resources at read time; Griffendo stores the structured "
                              f"EventData instead)" if "message" in lost_pos else f"needs {reason}")
        else:
            status = "fully_supported"
            if lost_exc:
                status = "partially_supported"
                notes.append("Exclusion(s) on " + ", ".join(sorted(lost_exc)) + " cannot be applied.")
            if lost_pos and status == "fully_supported" and not survivors_all:
                status = "partially_supported"
            if rule.get("if_fts"):
                status = "partially_supported"
                notes.append("First-time-seen key taken as the logon's target user and source workstation "
                             "(the decoder's <fts> list is not part of the supplied files).")
            if channels and all(c == schema.SYSMON for c in channels):
                optional.append(av.OPTIONAL_CHANNELS[schema.SYSMON])
            for provider in providers:
                product = next((name for key, name in OPTIONAL_PRODUCTS.items() if provider.lower() == key.lower()),
                               None)
                if product:
                    optional.append(f"{product} installed (writes to the Windows event log)")
            if rule["source_file"].startswith(("0601-", "0605-", "0615-")):
                optional.append({"0601-": "VIPRE antivirus", "0605-": "McAfee VirusScan",
                                 "0615-": "Microsoft Security Essentials / System Center Endpoint Protection"}
                                [rule["source_file"][:5]] + " installed (writes to the Windows event log)")
            if optional and status == "fully_supported":
                status = "requires_optional_source"
            codes_int = {int(c) for c in rule["event_codes"] if c.isdigit()}
            dc = codes_int & av.DC_EVENTS
            if dc and dc == codes_int:
                optional.append("Domain controller role")
                if status == "fully_supported":
                    status = "requires_optional_source"
            if lost_pos:
                notes.append("Branch(es) on " + ", ".join(sorted(lost_pos)) + " cannot match.")
            rule["status"], rule["reason"] = status, " ".join(notes)
        rule["optional_sources"] = sorted(set(optional))
        rule["kind"] = "wazuh"
    return rules


def _witness(flat: dict[str, Any], key: str, channel: str, eid: int | None) -> bool:
    return av.witness_event(flat, key, channel, eid) is not None
