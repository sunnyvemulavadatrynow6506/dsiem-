"""Build docs/Griffendo_Anomaly_Event_IDs_v2.xlsx from catalog/anomaly_catalog.json and the original spreadsheet.

Keeps the original workbook's look (Arial 10, navy headers, priority fills) and its
Summary / Anomaly Events / Notes structure, and adds the difference report.
"""
from __future__ import annotations

import json
from pathlib import Path

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "catalog" / "anomaly_catalog.json").read_text(encoding="utf-8"))
ORIGINAL = openpyxl.load_workbook(ROOT / "reference" / "Griffendo_Anomaly_Event_IDs.xlsx")["Anomaly Events"]
OUT = ROOT / "docs" / "Griffendo_Anomaly_Event_IDs_v2.xlsx"

NAVY = "FF123B63"
FILLS = {"Critical": "FFF8C9C9", "High": "FFFBDDB8", "Medium": "FFFFF3B8", "Optional": "FFD9E4F5",
         "Low": "FFE5EDF5", "Informational": "FFEEF1F4"}
BASE_CHANNELS = {"System", "Security", "Setup", "Application"}
F = Font(name="Arial", size=10)
FB = Font(name="Arial", size=10, bold=True)
FH = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
WRAP = Alignment(wrap_text=True, vertical="top")

rules = CATALOG["rules"]
by_key = {(r["channel"], r["event_id"]): r for r in rules}
by_id: dict[int, list[dict]] = {}
for r in rules:
    by_id.setdefault(r["event_id"], []).append(r)


def disposition(event_id: int, channel: str | None = None) -> str:
    matches = [r for r in by_id.get(event_id, []) if channel in (None, r["channel"])]
    if matches:
        r = matches[0]
        return f"In catalog as {r['rule_id']} ({r['severity']}, {'enabled' if r['enabled'] else 'disabled by default'})"
    reviewed = [x for x in CATALOG["reviewed_not_included"] if x["event_id"] == event_id and channel in (None, x["channel"])]
    if reviewed:
        return f"Reviewed, not included: {reviewed[0]['reason']}"
    return "Not in catalog"


def sheet(wb, title, headers, rows, widths, fill_col=None, freeze="A2"):
    ws = wb.create_sheet(title)
    ws.append(headers)
    for cell in ws[1]:
        cell.font, cell.fill, cell.alignment = FH, PatternFill("solid", fgColor=NAVY), WRAP
    for row in rows:
        ws.append(row)
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.font, cell.alignment = F, WRAP
        if fill_col is not None:
            value = row[fill_col].value
            if value in FILLS:
                row[fill_col].fill = PatternFill("solid", fgColor=FILLS[value])
                row[fill_col].font = FB
    for index, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(index)].width = width
    ws.freeze_panes = freeze
    ws.auto_filter.ref = ws.dimensions
    return ws


def main() -> None:
    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    # ---------------- Summary (formulas over the catalog sheet)
    ws = wb.create_sheet("Summary")
    ws["A1"] = "Griffendo - Event IDs Flagged as Anomaly on ID Alone (catalog " + CATALOG["catalog_version"] + ")"
    ws["A1"].font = Font(name="Arial", size=14, bold=True, color=NAVY)
    ws["A2"] = ("An event is an anomaly the moment its Event ID (on the rule's channel) appears in the last 7 days. "
                "No other field is checked. Counts below are formulas over the 'Anomaly Events' sheet.")
    ws["A2"].font = F
    ws.append([])
    ws.append(["Severity", "Rules", "Enabled", "Original channels", "Added channels", "From original sheet"])
    for cell in ws[4]:
        cell.font, cell.fill = FH, PatternFill("solid", fgColor=NAVY)
    severities = CATALOG["severity_order"]
    for i, severity in enumerate(severities, start=5):
        ws.append([
            severity,
            f"=COUNTIF('Anomaly Events'!$C:$C,A{i})",
            f"=COUNTIFS('Anomaly Events'!$C:$C,A{i},'Anomaly Events'!$I:$I,\"Yes\")",
            f"=COUNTIFS('Anomaly Events'!$C:$C,A{i},'Anomaly Events'!$I:$I,\"Yes\",'Anomaly Events'!$J:$J,\"Original channel\")",
            f"=COUNTIFS('Anomaly Events'!$C:$C,A{i},'Anomaly Events'!$I:$I,\"Yes\",'Anomaly Events'!$J:$J,\"Added channel\")",
            f"=COUNTIFS('Anomaly Events'!$C:$C,A{i},'Anomaly Events'!$L:$L,\">0\")",
        ])
        ws.cell(i, 1).fill = PatternFill("solid", fgColor=FILLS[severity])
    total = 5 + len(severities)
    ws.append(["Total"] + [f"=SUM({c}5:{c}{total - 1})" for c in "BCDEF"])
    for row in ws.iter_rows(min_row=5, max_row=total):
        for cell in row:
            cell.font = FB if row[0].row == total or cell.column == 1 else F
    ws.append([])
    ws.append(["'Optional' keeps the original sheet's Sysmon tier; it marks a prerequisite (Sysmon installed), not impact."])
    ws.append(["Original channels = System, Security, Setup, Application (what Griffendo collected before). Added channels are read only for the last 8 days."])
    ws.append(["Reviewed but not included: see 'Reviewed Not Included' (" + str(len(CATALOG["reviewed_not_included"])) + " IDs)."])
    for row in ws.iter_rows(min_row=total + 2):
        for cell in row:
            cell.font = F
    for col, width in zip("ABCDEF", (22, 10, 10, 18, 16, 20)):
        ws.column_dimensions[col].width = width

    # ---------------- full catalog
    rows = []
    for r in rules:
        rows.append([
            r["rule_id"], r["spreadsheet_priority"] or "", r["severity"], r["event_id"], r["name"], r["category"],
            r["channel"], r["expected_provider"], "Yes" if r["enabled"] else "No",
            "Original channel" if r["channel"] in BASE_CHANNELS else "Added channel",
            r["origin"], r["spreadsheet_row"] or 0,
            "Event ID present on this channel in 7-day window = anomaly" if r["enabled"] else "Disabled by default (catalogued)",
            ", ".join(r["details"]) or "-", r["prerequisite"], r["notes"], r["false_positives"], r["reference"], r["verification"],
        ])
    sheet(wb, "Anomaly Events",
          ["Rule ID", "Original priority", "Severity", "Event ID", "Anomaly name", "Category", "Log channel", "Expected provider",
           "Enabled", "Collector status", "Origin", "Original row #", "Flag rule", "Details to show analyst (not used for flagging)",
           "Prerequisite", "Notes", "Known benign causes", "Reference", "Verification"],
          rows, [11, 14, 13, 9, 40, 20, 34, 30, 9, 16, 12, 10, 34, 40, 34, 50, 34, 40, 30], fill_col=2, freeze="E2")

    # ---------------- the 47 original rows and their final status
    rows = []
    for values in ORIGINAL.iter_rows(min_row=2, values_only=True):
        number, priority, event_id, name, category, channel, _rule, collector, details = values[:9]
        if not number:
            continue
        r = next(x for x in rules if x["spreadsheet_row"] == number)
        changes = []
        if r["name"] != name:
            changes.append(f"name '{name}' -> '{r['name']}'")
        if r["category"] != category:
            changes.append(f"category '{category}' -> '{r['category']}'")
        if r["channel"] != channel:
            changes.append(f"channel '{channel}' -> '{r['channel']}'")
        status = "Kept, corrected: " + "; ".join(changes) if changes else "Kept unchanged"
        rows.append([number, priority, event_id, name, category, channel, collector, r["rule_id"], r["severity"],
                     "Implemented, enabled", status, r["notes"]])
    sheet(wb, "Original 47 Status",
          ["#", "Original priority", "Event ID", "Original name", "Original category", "Original channel",
           "Original collector status", "Rule ID", "Final severity", "Implementation", "Final status", "Verification notes"],
          rows, [5, 16, 9, 36, 20, 34, 18, 12, 13, 18, 50, 60], fill_col=8, freeze="D2")

    # ---------------- difference report
    diff = []
    for values in ORIGINAL.iter_rows(min_row=2, values_only=True):
        if values[0]:
            diff.append(["1. In spreadsheet, missing from the application's rules", values[2], values[5],
                         values[3], "Griffendo had no anomaly rules before this change; now " + disposition(values[2], None)])
    code_ids = [(4624, "Security", "app.py EVENT_LABELS; app.js"), (4625, "Security", "app.py EVENT_LABELS; app.js"),
                (4672, "Security", "app.py EVENT_LABELS; app.js"), (4688, "Security", "app.py EVENT_LABELS; app.js"),
                (7045, "System", "app.py EVENT_LABELS; app.js"), (7036, "System", "app.py EVENT_LABELS; app.js"),
                (4634, "Security", "app.js"), (4647, "Security", "app.js"), (4648, "Security", "app.js"),
                (4768, "Security", "app.js"), (4769, "Security", "app.js"), (4771, "Security", "app.js"),
                (4776, "Security", "app.js"), (4689, "Security", "app.js"), (1, "Microsoft-Windows-Sysmon/Operational", "app.js"),
                (5, "Microsoft-Windows-Sysmon/Operational", "app.js"), (3, "Microsoft-Windows-Sysmon/Operational", "app.js"),
                (7034, "System", "app.js"), (7035, "System", "app.js"), (7040, "System", "app.js"), (4697, "Security", "app.js"),
                (4673, "Security", "app.js"), (4674, "Security", "app.js"), (4720, "Security", "app.js"),
                (4722, "Security", "app.js"), (4723, "Security", "app.js"), (4724, "Security", "app.js"),
                (4725, "Security", "app.js"), (4726, "Security", "app.js"), (4728, "Security", "app.js"),
                (4732, "Security", "app.js"), (4738, "Security", "app.js"), (4740, "Security", "app.js"),
                (4756, "Security", "app.js"), (4719, "Security", "app.js"), (4739, "Security", "app.js"),
                (4902, "Security", "app.js"), (4904, "Security", "app.js"), (1102, "Security", "app.js"),
                (5156, "Security", "app.js"), (5157, "Security", "app.js"), (5158, "Security", "app.js")]
    sheet_ids = {v[2] for v in ORIGINAL.iter_rows(min_row=2, values_only=True) if v[0]}
    for event_id, channel, where in code_ids:
        if event_id not in sheet_ids:
            diff.append(["2. Referenced in application code, absent from spreadsheet", event_id, channel,
                         f"Found in {where} (labels / host activity groups, not detection rules)", disposition(event_id, channel)])
    prompt_ids = [4624, 4625, 4648, 4672, 4771, 4776, 4768, 4769, 4778, 4779, 4723, 4724, 4728, 4729, 4732, 4737, 4756,
                  4757, 4704, 4705, 4688, 4689, 4657, 4656, 4660, 4663, 4670, 4713, 4907, 1101, 4608, 4609, 6005, 6006,
                  1074, 7031, 7034, 4103, 4104, 106, 140, 141, 3003]
    for event_id in prompt_ids:
        if event_id not in sheet_ids:
            diff.append(["3. Named in the development prompt, absent from spreadsheet", event_id,
                         (by_id.get(event_id) or [{"channel": "(see reason)"}])[0]["channel"], "Prompt candidate list",
                         disposition(event_id)])
    for r in rules:
        if r["origin"] == "research":
            diff.append(["4. New from research", r["event_id"], r["channel"], r["name"],
                         f"Added as {r['rule_id']} ({r['severity']}, {'enabled' if r['enabled'] else 'disabled'}); source: {r['reference']}"])
    dupes = [
        (1116, "Spreadsheet 'Malware detected (Defender)' vs prompt 'Malware detected by Windows Defender'", "Same rule; spreadsheet name kept."),
        (1117, "Spreadsheet 'Malware action taken (Defender)' vs prompt 'Windows Defender malware action taken'", "Same rule; spreadsheet name kept."),
        (4740, "Spreadsheet 'User account lockout' vs prompt 'User account locked out'", "Renamed to 'User account locked out'."),
        (41, "Spreadsheet 'Kernel-Power: reboot without clean shutdown' vs prompt 'Kernel-Power unexpected restart or shutdown'", "Spreadsheet name kept (matches Microsoft wording)."),
        (6008, "Spreadsheet 'Unexpected server shutdown' vs prompt 'Unexpected server shutdown' / section 8 'previous shutdown was unexpected'", "Renamed 'Previous system shutdown was unexpected'."),
        (4731, "Spreadsheet 'Local group created' vs prompt 'Local security-enabled group created'", "Same rule; Microsoft wording recorded in notes."),
        (6416, "Spreadsheet category 'Data exfiltration' vs prompt 'Device monitoring'", "Category set to 'Device monitoring'."),
        (8, "Spreadsheet category 'Defense evasion' vs prompt 'Process activity'", "Spreadsheet category kept (CreateRemoteThread = injection, ATT&CK defense evasion)."),
        (5025, "Spreadsheet channel 'Security' vs prompt 'Windows Firewall With Advanced Security/Firewall, subject to verification'", "Verified: Security log (Audit Other System Events). Spreadsheet was right."),
        (1100, "Spreadsheet channel 'Security' vs prompt 'Verify the provider and channel'", "Verified: Security log, provider Microsoft-Windows-Eventlog."),
        (4697, "Listed twice in the prompt (catalog and candidates)", "One rule (SEC-4697)."),
        (4698, "Same action recorded by Security 4698 and Task Scheduler 106", "Both kept as separate rules on separate channels; one task creation can yield two detections."),
        (4702, "Same action recorded by Security 4702 and Task Scheduler 140", "Both kept; see above."),
        (4699, "Same action recorded by Security 4699 and Task Scheduler 141", "Both kept; see above."),
        (7045, "Same service installation recorded by System 7045 and Security 4697", "Both kept (different logs, different prerequisites)."),
    ]
    for event_id, item, outcome in dupes:
        diff.append(["5. Duplicates / differing names, categories or channels", event_id, "", item, outcome])
    corrections = [
        (6008, "Name implied servers only and current-time shutdown; it is logged at the next boot for any Windows system.", "Renamed."),
        (6416, "'Data exfiltration' and '(USB)' over-claimed: any Plug and Play device; recognising a device is not exfiltration.", "Category and name corrected."),
        (1100, "Logged at every normal shutdown/restart.", "Kept as rule (ID-only contract); benign cause documented."),
        (104, "Detail 'UserName' is the SubjectUserName field; fires for logs other than Security.", "Detail field corrected."),
        (4950, "Detail 'SubjectUserName' does not exist in 4950; setting is SettingType/SettingValue.", "Detail fields corrected."),
        (5142, "Detail 'SharePath' is ShareLocalPath in the event.", "Detail field corrected."),
        (4740, "TargetDomainName holds the caller computer (source host).", "Documented."),
        (3003, "Could not be matched to a standard shutdown event.", "Not treated as shutdown; not included."),
        (4625, "A failed logon; not evidence of brute force by itself.", "Named 'Failed logon'."),
        (4624, "Successful logon of any type; not RDP unless LogonType 10.", "Named 'Successful logon'; disabled by default."),
        (4609, "Documented but rarely written on modern Windows.", "Informational; absence is not meaningful."),
        (1, "ID 1 in System is used by several providers.", "No System-1 rule; rules are channel-scoped."),
        (4907, "Microsoft rates Medium; bulk-generated by servicing.", "Severity Low (documented deviation)."),
        (1149, "Successful network-level RDP authentication, not an interactive logon.", "Named accordingly."),
    ]
    for event_id, issue, outcome in corrections:
        diff.append(["6. Incorrect, ambiguous or unverified descriptions", event_id, "", issue, outcome])
    for channel in sorted({r["channel"] for r in rules} - BASE_CHANNELS):
        enabled = sum(1 for r in rules if r["channel"] == channel and r["enabled"])
        diff.append(["7. Channels the original collector did not support", "", channel,
                     f"{enabled} enabled rule(s); original collector read only System/Security/Setup/Application and the receiver rejected other channels",
                     "Collector now reads it (8-day bound) when an enabled rule needs it; receiver accepts it; availability shown per channel"
                     if enabled else "Only disabled rules use it; not collected unless such a rule is enabled"])
    sheet(wb, "Difference Report", ["Section", "Event ID", "Channel", "Item", "Outcome"], diff, [44, 9, 40, 60, 70])

    sheet(wb, "Reviewed Not Included", ["Event ID", "Channel", "Found in", "Reason"],
          [[x["event_id"], x["channel"], x["found_in"], x["reason"]] for x in CATALOG["reviewed_not_included"]], [9, 40, 34, 90])

    channel_rows = []
    for channel in dict.fromkeys(["System", "Security", "Setup", "Application"] + [r["channel"] for r in rules]):
        enabled = sum(1 for r in rules if r["channel"] == channel and r["enabled"])
        total_rules = sum(1 for r in rules if r["channel"] == channel)
        prereq = {
            "Microsoft-Windows-Windows Defender/Operational": "Present when Microsoft Defender Antivirus is active; other AV products may disable it.",
            "Microsoft-Windows-WMI-Activity/Operational": "Present on supported Windows versions.",
            "Microsoft-Windows-Sysmon/Operational": "Only exists if Sysmon is installed. Griffendo does not install it.",
            "Microsoft-Windows-TaskScheduler/Operational": "Exists but disabled by default on many versions ('Enable All Tasks History').",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": "Present on systems with Remote Desktop Services components.",
            "Microsoft-Windows-PowerShell/Operational": "Present; 4103/4104 need module / script block logging policy.",
            "Security": "Reading requires Administrator. Many rules need their audit subcategory enabled (auditpol).",
        }.get(channel, "")
        status = "Collected before and after" if channel in BASE_CHANNELS else (
            "Added: collected when enabled rules need it" if enabled else "Not collected (only disabled rules)")
        channel_rows.append([channel, total_rules, enabled, status, prereq])
    sheet(wb, "Channels", ["Channel", "Rules", "Enabled rules", "Collection", "Availability / prerequisite"],
          channel_rows, [62, 8, 13, 40, 80])

    notes = [
        ("Rule", "Query the last 7 days (rolling, start and end inclusive, UTC, on the event's own time). Any event whose channel + Event ID matches an enabled rule is flagged. No threshold, field match or correlation is used."),
        ("Identity / duplicates", "Each matching event is its own detection, keyed by sha256(host|channel|record id|raw XML) + rule id. Reprocessing never duplicates; distinct events are never merged. Grouping (rule x host) is display-only."),
        ("Removed events (original note)", "The original sheet left out events that need other data to be meaningful. Under the ID-only contract several were re-added at the severities shown in this catalog (4625, 4648, 4723, 4724, 4732, 4657, 4771, 4778, 4779, 1074, 7031, 7034, 1149); high-volume ones are catalogued but disabled (4624, 4672, 4688, 4663, 4670, 4776, 4798, 4799, 5140, 5145, 4104)."),
        ("False positives", "Windows Update, installers and Group Policy can legitimately trigger 4698, 4702, 7045, 7040, 4719 and 4907; planned maintenance or power loss triggers 6008 and 41; 1100 is logged at every clean shutdown. A flag means the ID occurred, not that it was malicious."),
        ("Audit policy", "Many Security events exist only if the matching audit subcategory is enabled. Check with: auditpol /get /category:* . Griffendo does not change audit policy."),
        ("Collector channels", "Griffendo.exe was a compiled PyInstaller build; its source was reconstructed from the bundled bytecode (verified instruction-for-instruction) to inspect the collector: it read System, Security, Setup and Application only, and the receiver rejected other channels. Both now support the added channels."),
        ("Configuring", "The catalog is JSON (catalog/anomaly_catalog.json, bundled in the exe). Override it by placing anomaly_catalog.json in %LOCALAPPDATA%\\Griffendo or setting GRIFFENDO_CATALOG. Disabled rules can be enabled by setting \"enabled\": true."),
        ("3003", "Event ID 3003 from the sample list could not be matched to a standard shutdown event, so it is not included."),
    ]
    sheet(wb, "Notes", ["Topic", "Note"], notes, [24, 120])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    wb.save(OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
