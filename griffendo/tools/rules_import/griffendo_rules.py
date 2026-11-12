"""Griffendo-authored correlation, chain and behaviour rules (single-host, local event data only)."""
from __future__ import annotations

from logplatform.detection.engine import schema

SYSMON, SECURITY, SYSTEM = schema.SYSMON, schema.SECURITY, schema.SYSTEM
PROCESS_START = [{"channel": SYSMON, "event_ids": [1]}, {"channel": SECURITY, "event_ids": [4688]}]
START = {"any": [{"all": [{"field": "winlog.channel", "op": "eq", "values": [SYSMON], "ci": True},
                          {"field": "event.code", "op": "eq", "values": ["1"]}]},
                 {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                          {"field": "event.code", "op": "eq", "values": ["4688"]}]}]}
OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
          "visio.exe"]
INTERPRETERS = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe"]
SOURCE = {"platform": "Griffendo", "license": "Griffendo (Soarg)", "author": "Griffendo v5"}


def _proc(names: list[str], extra: list | None = None) -> dict:
    return {"all": [START, {"field": "process.name", "op": "eq", "values": names, "ci": True}, *(extra or [])]}


def specs() -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    task_by_schtasks = _proc(["schtasks.exe"], [{"field": "process.args", "op": "eq", "values": ["/create", "-create"],
                                                 "ci": True}])
    task_event = {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                          {"field": "event.code", "op": "eq", "values": ["4698"]}]}
    out.append(({
        "id": "CHN-001", "name": "Office application started a script interpreter that created a scheduled task",
        "description": "An Office process started a script interpreter (directly or through descendants), and that "
                       "interpreter or one of its children created a scheduled task (schtasks /create), or a task "
                       "was registered (4698) in the interpreter's logon session. Local-only variant of the "
                       "'document -> script -> network -> persistence' chain: it does not require network telemetry.",
        "category": "Persistence", "severity": "High", "risk_score": 80, "confidence": "high", "kind": "chain",
        "origin": "griffendo", "enabled": True,
        "chain": {"window_seconds": 900, "steps": [
            {"name": "Office process starts", "condition": _proc(OFFICE), "sources": PROCESS_START},
            {"name": "Script interpreter starts", "condition": _proc(INTERPRETERS), "sources": PROCESS_START,
             "relation": {"type": "descendant_of", "step": 0, "max_depth": 4}},
            {"name": "Scheduled task created", "condition": {"any": [task_by_schtasks, task_event]},
             "sources": PROCESS_START + [{"channel": SECURITY, "event_ids": [4698]}],
             "relation": {"any": [{"type": "process_or_descendant", "step": 1},
                                  {"type": "same_logon", "step": 1, "only_without_process": True}]}}]},
        "mitre": [{"tactic": "Execution", "technique": "T1204.002", "name": "Malicious File"},
                  {"tactic": "Persistence", "technique": "T1053.005", "name": "Scheduled Task"}],
        "investigation": "Open the Office document the user worked with, review the interpreter's command line and "
                         "the task's action (Security 4698 TaskContent or the schtasks arguments), and check what "
                         "the task runs.",
        "support": {"status": "fully_supported", "notes": "Needs process creation events (Sysmon 1, or Security "
                    "4688 with command-line auditing for schtasks arguments) and, for the 4698 branch, "
                    "'Audit Other Object Access Events'.", "optional_sources": []},
        "source": SOURCE, "modifications": [],
    }, "correlation"))
    out.append(({
        "id": "CHN-002", "name": "Office application started a script interpreter that made a network connection and "
                                "created a scheduled task",
        "description": "Full chain: Office -> script interpreter -> outbound network connection from that "
                       "interpreter (Sysmon 3) -> scheduled task creation by it or its children.",
        "category": "Command and Control", "severity": "Critical", "risk_score": 92, "confidence": "high",
        "kind": "chain", "origin": "griffendo", "enabled": True,
        "chain": {"window_seconds": 900, "steps": [
            {"name": "Office process starts", "condition": _proc(OFFICE), "sources": PROCESS_START},
            {"name": "Script interpreter starts", "condition": _proc(INTERPRETERS), "sources": PROCESS_START,
             "relation": {"type": "descendant_of", "step": 0, "max_depth": 4}},
            {"name": "Interpreter connects out", "condition": {"all": [
                {"field": "winlog.channel", "op": "eq", "values": [SYSMON], "ci": True},
                {"field": "event.code", "op": "eq", "values": ["3"]},
                {"not": {"field": "destination.ip", "op": "cidr",
                         "values": ["127.0.0.0/8", "::1/128"]}}]},
             "sources": [{"channel": SYSMON, "event_ids": [3]}],
             "relation": {"type": "process_or_descendant", "step": 1}},
            {"name": "Scheduled task created", "condition": {"any": [task_by_schtasks, task_event]},
             "sources": PROCESS_START + [{"channel": SECURITY, "event_ids": [4698]}],
             "relation": {"any": [{"type": "process_or_descendant", "step": 1},
                                  {"type": "same_logon", "step": 1, "only_without_process": True}]}}]},
        "mitre": [{"tactic": "Execution", "technique": "T1204.002", "name": "Malicious File"},
                  {"tactic": "Command and Control", "technique": "T1105", "name": "Ingress Tool Transfer"},
                  {"tactic": "Persistence", "technique": "T1053.005", "name": "Scheduled Task"}],
        "investigation": "As CHN-001, plus the destination of the connection.",
        "support": {"status": "requires_optional_source", "notes": "The network step needs Sysmon event 3.",
                    "optional_sources": ["Sysmon (Microsoft-Windows-Sysmon/Operational) installed and collected"]},
        "source": SOURCE, "modifications": [],
    }, "correlation"))
    out.append(({
        "id": "CHN-003", "name": "New service installed and its program started",
        "description": "A service was installed (System 7045 or Security 4697) and, within 15 minutes, a process "
                       "started from the service's image path or the Service Control Manager reported the "
                       "service running (7036).",
        "category": "Persistence", "severity": "High", "risk_score": 72, "confidence": "high", "kind": "chain",
        "origin": "griffendo", "enabled": True,
        "chain": {"window_seconds": 900, "steps": [
            {"name": "Service installed", "condition": {"any": [
                {"all": [{"field": "winlog.channel", "op": "eq", "values": [SYSTEM], "ci": True},
                         {"field": "event.code", "op": "eq", "values": ["7045"]}]},
                {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                         {"field": "event.code", "op": "eq", "values": ["4697"]}]}]},
             "sources": [{"channel": SYSTEM, "event_ids": [7045]}, {"channel": SECURITY, "event_ids": [4697]}]},
            {"name": "Service program runs", "condition": {"any": [
                START,
                {"all": [{"field": "winlog.channel", "op": "eq", "values": [SYSTEM], "ci": True},
                         {"field": "event.code", "op": "eq", "values": ["7036"]},
                         {"field": "winlog.event_data.param2", "op": "eq", "values": ["running"], "ci": True}]}]},
             "sources": PROCESS_START + [{"channel": SYSTEM, "event_ids": [7036]}],
             "relation": {"any": [{"type": "field_equals", "step": 0, "field": "process.executable", "other": "file.path"},
                                  {"type": "field_equals", "step": 0, "field": "service.name", "other": "service.name"}]}}]},
        "mitre": [{"tactic": "Persistence", "technique": "T1543.003", "name": "Windows Service"}],
        "investigation": "Check who installed the service (4697 Subject), the binary's path, signer and hash, "
                         "and what it did after starting.",
        "support": {"status": "fully_supported", "notes": "7036 is written by the Service Control Manager in the "
                    "System log; process-path matching needs Sysmon 1 or 4688.", "optional_sources": []},
        "source": SOURCE, "modifications": ["The 7036 match compares the service name only (param1); localised "
                                            "Windows writes the state text in its own language."],
    }, "correlation"))
    run_keys = ["*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                "*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                "*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                "*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"]
    out.append(({
        "id": "CHN-004", "name": "Script interpreter set an autostart registry value",
        "description": "A script interpreter (or a process it started) wrote a Run/RunOnce or Winlogon autostart "
                       "value within 10 minutes of starting.",
        "category": "Persistence", "severity": "High", "risk_score": 75, "confidence": "high", "kind": "chain",
        "origin": "griffendo", "enabled": True,
        "chain": {"window_seconds": 600, "steps": [
            {"name": "Script interpreter starts", "condition": _proc(INTERPRETERS), "sources": PROCESS_START},
            {"name": "Autostart value written", "condition": {"all": [
                {"field": "winlog.channel", "op": "eq", "values": [SYSMON], "ci": True},
                {"field": "event.code", "op": "eq", "values": ["13"]},
                {"field": "registry.path", "op": "wildcard", "values": run_keys, "ci": True}]},
             "sources": [{"channel": SYSMON, "event_ids": [13]}],
             "relation": {"type": "process_or_descendant", "step": 0}}]},
        "mitre": [{"tactic": "Persistence", "technique": "T1547.001", "name": "Registry Run Keys / Startup Folder"}],
        "investigation": "Read the value data (the program that will run at logon) and the interpreter's command line.",
        "support": {"status": "requires_optional_source", "notes": "Registry writes come from Sysmon 13.",
                    "optional_sources": ["Sysmon (Microsoft-Windows-Sysmon/Operational) installed and collected"]},
        "source": SOURCE, "modifications": [],
    }, "correlation"))
    admin_actions = {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                             {"field": "event.code", "op": "eq",
                              "values": ["4720", "4732", "4728", "4756", "4698", "4697", "1102", "4719", "4738"]}]}
    out.append(({
        "id": "CHN-005", "name": "Remote logon followed by administrative changes in the same session",
        "description": "A network or Remote Desktop logon by a user account, then - in the same logon session, "
                       "within 30 minutes - account creation, group membership change, scheduled task or service "
                       "installation, audit policy change or a cleared Security log.",
        "category": "Privilege Escalation", "severity": "High", "risk_score": 78, "confidence": "high",
        "kind": "chain", "origin": "griffendo", "enabled": True,
        "chain": {"window_seconds": 1800, "steps": [
            {"name": "Remote logon", "condition": {"all": [
                {"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                {"field": "event.code", "op": "eq", "values": ["4624"]},
                {"field": "winlog.logon.type", "op": "eq", "values": ["Network", "RemoteInteractive"]},
                {"not": {"field": "user.name", "op": "wildcard", "values": ["*$"]}},
                {"not": {"field": "user.name", "op": "eq", "values": ["ANONYMOUS LOGON"], "ci": True}}]},
             "sources": [{"channel": SECURITY, "event_ids": [4624]}]},
            {"name": "Administrative change", "condition": admin_actions,
             "sources": [{"channel": SECURITY, "event_ids": [4720, 4732, 4728, 4756, 4698, 4697, 1102, 4719, 4738]}],
             "relation": {"type": "same_logon", "step": 0}}]},
        "mitre": [{"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
                  {"tactic": "Persistence", "technique": "T1136.001", "name": "Local Account"}],
        "investigation": "Confirm the source address and whether the change was planned administration.",
        "support": {"status": "fully_supported", "notes": "Security auditing of logons and account management.",
                    "optional_sources": []},
        "source": SOURCE, "modifications": [],
    }, "correlation"))
    out.append(({
        "id": "COR-001", "name": "Repeated failed logons followed by a successful logon",
        "description": "At least 10 failed logons (4625) for one account within 5 minutes, then a successful logon "
                       "(4624) for that account within the same 5-minute span.",
        "category": "Credential Access", "severity": "High", "risk_score": 73, "confidence": "high",
        "kind": "sequence", "origin": "griffendo", "enabled": True, "maxspan": 300,
        "steps": [
            {"condition": {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                                   {"field": "event.code", "op": "eq", "values": ["4625"]}]},
             "sources": [{"channel": SECURITY, "event_ids": [4625]}], "by": ["user.name"], "runs": 10},
            {"condition": {"all": [{"field": "winlog.channel", "op": "eq", "values": [SECURITY], "ci": True},
                                   {"field": "event.code", "op": "eq", "values": ["4624"]}]},
             "sources": [{"channel": SECURITY, "event_ids": [4624]}], "by": ["user.name"]}],
        "mitre": [{"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"}],
        "investigation": "Compare the source addresses of the failures and the success (shown in the evidence), "
                         "and check what the session did next.",
        "support": {"status": "fully_supported", "notes": "Joined on the account name (case-insensitive); the source "
                    "address is shown but not required, because it is often '-' for local logons.",
                    "optional_sources": []},
        "source": SOURCE, "modifications": [],
    }, "correlation"))
    for rule_id, name, family, severity, description in (
            ("BEH-PROCESS", "Unusual process activity for this host", "process", "Medium",
             "Process creation that the host's learned baseline rates as rare: new parent/child pairs, new "
             "programs for a user, unusual command-line length/entropy or time of day."),
            ("BEH-LOGON", "Unusual logon for this host", "logon", "Medium",
             "A logon whose type, source address or hour is rare for that account on this host."),
            ("BEH-PERSISTENCE", "Unusual service or scheduled task for this host", "persistence", "Medium",
             "A service installation or scheduled task whose name the host has not seen in its baseline."),
            ("BEH-VOLUME", "Unusual event volume for this host", "volume", "Low",
             "A one- or five-minute bucket with far more events, process starts, failed logons or errors than "
             "the host's learned rate.")):
        out.append(({
            "id": rule_id, "name": name, "description": description, "category": "Behaviour", "severity": severity,
            "confidence": "medium", "kind": "behavior", "origin": "griffendo", "enabled": True,
            "behavior": {"family": family}, "sources": [],
            "mitre": [], "investigation": "Open the feature breakdown: it lists which observed values were rare and "
                                          "how they compare with the baseline.",
            "support": {"status": "fully_supported", "notes": "Behaviour model; alerts only in the Active stage.",
                        "optional_sources": []},
            "source": SOURCE, "modifications": [],
        }, "behavior"))
    return out
