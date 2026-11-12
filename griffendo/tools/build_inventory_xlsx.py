"""Write docs/Griffendo_v5_Rule_Inventory.xlsx from docs/rules_inventory.json (run after generate.py)."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logplatform.detection.engine import schema  # noqa: E402

STATUS_LABEL = {"fully_supported": "Fully supported", "requires_optional_source": "Requires optional source",
                "partially_supported": "Partially supported", "unsupported": "Unsupported (excluded)"}
HEAD = Font(bold=True, color="FFFFFF")
FILL = PatternFill("solid", fgColor="123B63")


def sheet(wb, title, header, rows, widths):
    ws = wb.create_sheet(title)
    ws.append(header)
    for cell in ws[1]:
        cell.font, cell.fill = HEAD, FILL
        cell.alignment = Alignment(wrap_text=True, vertical="top")
    for row in rows:
        ws.append(row)
    for index, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(index)].width = width
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    return ws


def main() -> None:
    inventory = json.loads((ROOT / "docs" / "rules_inventory.json").read_text(encoding="utf-8"))
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    summary.append(["Source", "Rules inspected", "Fully supported", "Requires optional source", "Partially supported",
                    "Unsupported (excluded)", "Rule files generated"])
    for cell in summary[1]:
        cell.font, cell.fill = HEAD, FILL
    for source in ("Elastic", "Wazuh", "Griffendo catalog", "Griffendo"):
        items = [e for e in inventory if e["source"] == source]
        counts = Counter(e["status"] for e in items)
        summary.append([source, len(items), counts["fully_supported"], counts["requires_optional_source"],
                        counts["partially_supported"], counts["unsupported"], sum(1 for e in items if e.get("module"))])
    summary.append([])
    summary.append(["Outstanding: ES|QL rules over local Windows logs not yet ported",
                    sum(1 for e in inventory if e["reason"].startswith("OUTSTANDING"))])
    for col, width in zip("ABCDEFG", (34, 16, 16, 24, 20, 22, 20)):
        summary.column_dimensions[col].width = width
    columns = ["source", "file", "source_rule_id", "griffendo_id", "name", "status", "reason", "type", "language",
               "kind", "severity", "risk_score", "level", "tactic", "mitre", "channels", "event_ids", "correlation",
               "optional_sources", "modifications", "confidence", "witness", "license", "indexes", "module"]
    headers = ["Source", "Source file", "Original rule ID", "Griffendo rule ID", "Name", "Status", "Reason / notes",
               "Rule type", "Language", "Griffendo kind", "Severity", "Risk score", "Wazuh level", "Tactic", "MITRE ATT&CK",
               "Required channels", "Event IDs", "Correlation required", "Optional sources", "Local modifications",
               "Confidence", "Positive test event generated", "Licence", "Original data sources", "Rule module"]
    widths = [10, 34, 26, 22, 46, 22, 60, 12, 12, 12, 11, 9, 9, 18, 18, 34, 20, 12, 34, 50, 10, 12, 18, 40, 46]

    def rows(items):
        out = []
        for e in items:
            row = []
            for key in columns:
                value = e.get(key, "")
                if key == "status":
                    value = STATUS_LABEL.get(value, value)
                row.append(value if not isinstance(value, (list, dict)) else json.dumps(value))
            out.append(row)
        return out
    sheet(wb, "Elastic rules", headers, rows([e for e in inventory if e["source"] == "Elastic"]), widths)
    sheet(wb, "Wazuh rules", headers, rows([e for e in inventory if e["source"] == "Wazuh"]), widths)
    sheet(wb, "Griffendo rules", headers, rows([e for e in inventory if e["source"].startswith("Griffendo")]), widths)
    sheet(wb, "Excluded", ["Source", "File", "Original rule ID", "Name", "Reason"],
          [[e["source"], e["file"], e["source_rule_id"], e["name"], e["reason"]] for e in inventory
           if e["status"] == "unsupported"], [10, 40, 26, 50, 90])
    mapping = []
    for key, source in schema.SOURCES.items():
        mapping.append([key, source["channel"], ", ".join(map(str, source["event_ids"])), source["category"],
                        ", ".join(sorted(source["fields"]))])
    for channel, fields in schema.GENERIC_FIELDS.items():
        mapping.append([f"generic ({channel})", channel, "any", "-", ", ".join(sorted(fields))])
    mapping.append(["every event", "any", "any", "-", ", ".join(sorted(schema.COMMON_FIELDS)) +
                    ", winlog.event_data.<Name> (raw EventData)"])
    sheet(wb, "Field availability", ["Source", "Channel", "Event IDs", "EQL category", "Normalized fields produced"],
          mapping, [16, 44, 14, 12, 120])
    sheet(wb, "Licences", ["Source", "Licence", "Notes"], [
        ["Elastic detection-rules (windows.zip)", "Elastic License 2.0",
         "Use, copying, modification and redistribution allowed; may not be provided to third parties as a hosted or "
         "managed service, and licence notices must be kept. Each rule module keeps the notice, original rule ID, "
         "file and query."],
        ["Wazuh ruleset (New folder.zip)", "GNU GPL v2",
         "Copyleft: distributing Griffendo with these translated rules outside the organisation may require "
         "offering the corresponding source under GPLv2. Seek legal review before external distribution; the Wazuh "
         "rules are generated into separate modules (WAZ-*) and can be left out of a build."],
        ["Griffendo catalog and correlation rules", "Griffendo (Soarg)", "Authored for Griffendo."]], [40, 22, 120])
    out = ROOT / "docs" / "Griffendo_v5_Rule_Inventory.xlsx"
    wb.save(out)
    print(out)


if __name__ == "__main__":
    main()
