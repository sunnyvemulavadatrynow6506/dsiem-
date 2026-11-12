"""Build catalog/anomaly_catalog.json, the runtime detection catalog.

This file is the single reviewed definition of every rule.  The JSON it writes
is what the receiver loads, and the catalog report (tools/build_report.py)
reads the same JSON, so the app and the report cannot drift apart.

Detection contract (enforced by logplatform/anomalies.py, not by this file):
an event whose (channel, Event ID) matches an *enabled* rule and whose time
falls inside the analysis window is an anomaly.  Nothing else is checked.
"details" below are only the fields shown to the analyst.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CATALOG_VERSION = "2026.10.26-1"

SEC = "Security"
SYS = "System"
DEF = "Microsoft-Windows-Windows Defender/Operational"
WMI = "Microsoft-Windows-WMI-Activity/Operational"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
TASK = "Microsoft-Windows-TaskScheduler/Operational"
RDP = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"

P_AUDIT = "Microsoft-Windows-Security-Auditing"
P_EVENTLOG = "Microsoft-Windows-Eventlog"   # Security-log service events (1100-1108)
P_EVENTLOG_SYS = "EventLog"                 # System-log service events (6005/6006/6008)
P_SCM = "Service Control Manager"
P_KP = "Microsoft-Windows-Kernel-Power"
P_DEF = "Microsoft-Windows-Windows Defender"
P_WMI = "Microsoft-Windows-WMI-Activity"
P_SYSMON = "Microsoft-Windows-Sysmon"
P_TASK = "Microsoft-Windows-TaskScheduler"
P_RDP = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
P_PS = "Microsoft-Windows-PowerShell"
P_USER32 = "User32"

PREFIX = {SEC: "SEC", SYS: "SYS", DEF: "DEF", WMI: "WMI", SYSMON: "SYSMON", TASK: "TASK", RDP: "RDP", PS: "PS"}

REF_APPX_L = "Microsoft Learn - AD DS 'Appendix L: Events to Monitor'"
REF_AUDIT = "Microsoft Learn - Windows security audit event reference (event-{id})"
REF_OTHER_SYS = "Microsoft Learn - 'Audit Other System Events' (5024-5037)"
REF_DEF = "Microsoft Learn - Microsoft Defender Antivirus event IDs (MALWAREPROTECTION_* list)"
REF_SYSMON = "Microsoft Learn - Sysinternals Sysmon, 'Events' section"
REF_EVENTLOG = "Microsoft Learn - Event Log service events (1100-1108 / 104 / 6005-6008)"
REF_SCM = "Microsoft Learn - Service Control Manager events"
REF_KP = "Microsoft Learn - Kernel-Power event 41 troubleshooting"
REF_TASK = "Microsoft Learn - Task Scheduler 'General Task Registration' events 106/140/141"
REF_WMI = "Microsoft Learn - WMI-Activity tracing; community WMI-persistence detections (Sigma win_wmi_persistence)"
REF_RDP = "Microsoft Learn - Remote Desktop Services RemoteConnectionManager events"
REF_PS = "Microsoft Learn - about_Logging_Windows (PowerShell 4103/4104)"

FP_UPDATES = "Windows Update, installers and Group Policy can legitimately generate this event."

rules: list[dict] = []


def rule(row, priority, event_id, name, category, channel, provider, details, *, severity=None,
         enabled=True, origin="spreadsheet", prerequisite="", notes="", false_positives="",
         reference="", verification="Verified against Microsoft documentation"):
    sev = severity or {"Critical": "Critical", "High": "High", "Medium": "Medium",
                       "Optional (Sysmon)": "Optional"}[priority]
    rules.append({
        "rule_id": f"{PREFIX[channel]}-{event_id}",
        "event_id": event_id,
        "channel": channel,
        "expected_provider": provider,
        "name": name,
        "category": category,
        "severity": sev,
        "enabled": enabled,
        "origin": origin,
        "spreadsheet_row": row,
        "spreadsheet_priority": priority if row else None,
        "details": details,
        "prerequisite": prerequisite,
        "notes": notes,
        "false_positives": false_positives,
        "reference": reference.replace("{id}", str(event_id)),
        "verification": verification,
    })


# ---------------------------------------------------------------- spreadsheet (47 rows, order preserved)
rule(1, "Critical", 1102, "Security audit log cleared", "Defense evasion", SEC, P_EVENTLOG,
     ["SubjectUserName", "SubjectDomainName"], reference=REF_APPX_L,
     notes="Logged by the Event Log service (provider Microsoft-Windows-Eventlog), not by Security-Auditing.")
rule(2, "Critical", 104, "Event log cleared", "Defense evasion", SYS, P_EVENTLOG,
     ["SubjectUserName", "Channel", "BackupPath"], reference=REF_EVENTLOG,
     notes="Raised in the System log when any log other than Security is cleared; the cleared log is in 'Channel'. "
           "Spreadsheet detail 'UserName' corresponds to the SubjectUserName field.")
rule(3, "Critical", 4719, "System audit policy changed", "Defense evasion", SEC, P_AUDIT,
     ["SubjectUserName", "CategoryId", "SubcategoryId", "AuditPolicyChanges"], reference=REF_APPX_L,
     false_positives=FP_UPDATES, prerequisite="Audit Policy Change subcategory (Success).")
rule(4, "Critical", 7045, "New service installed", "Persistence", SYS, P_SCM,
     ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"], reference=REF_SCM,
     false_positives=FP_UPDATES)
rule(5, "Critical", 4697, "Service installed on the system", "Persistence", SEC, P_AUDIT,
     ["ServiceName", "ServiceFileName", "ServiceAccount", "SubjectUserName"], reference=REF_AUDIT,
     prerequisite="Audit Security System Extension (Success).", false_positives=FP_UPDATES)
rule(6, "Critical", 1116, "Malware detected (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Severity Name", "Path", "Process Name", "Detection User"], reference=REF_DEF,
     notes="MALWAREPROTECTION_STATE_MALWARE_DETECTED.")
rule(7, "Critical", 1117, "Malware action taken (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Action Name", "Path", "Process Name"], reference=REF_DEF,
     notes="MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN.")
rule(8, "Critical", 5001, "Defender real-time protection disabled", "Defense evasion", DEF, P_DEF, [],
     reference=REF_DEF, notes="MALWAREPROTECTION_RTP_DISABLED.")
rule(9, "Critical", 5010, "Defender scanning disabled", "Defense evasion", DEF, P_DEF, [],
     reference=REF_DEF, notes="MALWAREPROTECTION_ANTISPYWARE_DISABLED: scanning for malware and other potentially unwanted software is disabled.")
rule(10, "Critical", 5012, "Defender virus scanning disabled", "Defense evasion", DEF, P_DEF, [],
     reference=REF_DEF, notes="MALWAREPROTECTION_ANTIVIRUS_DISABLED.")
rule(11, "Critical", 5861, "WMI permanent event subscription", "Persistence", WMI, P_WMI,
     ["Namespace", "ESS", "CONSUMER", "PossibleCause"], reference=REF_WMI,
     notes="Logged when a permanent WMI event consumer is bound to a filter. Some management agents (SCCM, AV) register legitimate bindings.")
rule(12, "High", 4720, "Local user account created", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "TargetDomainName", "SubjectUserName"], reference=REF_AUDIT,
     notes="Also raised on domain controllers for domain accounts.")
rule(13, "High", 4698, "Scheduled task created", "Persistence", SEC, P_AUDIT,
     ["TaskName", "TaskContent", "SubjectUserName"], reference=REF_AUDIT,
     prerequisite="Audit Other Object Access Events (Success).", false_positives=FP_UPDATES)
rule(14, "High", 4702, "Scheduled task updated", "Persistence", SEC, P_AUDIT,
     ["TaskName", "TaskContentNew", "SubjectUserName"], reference=REF_AUDIT,
     prerequisite="Audit Other Object Access Events (Success).", false_positives=FP_UPDATES)
rule(15, "High", 4726, "User account deleted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(16, "High", 4740, "User account locked out", "Authentication", SEC, P_AUDIT,
     ["TargetUserName", "TargetDomainName", "SubjectUserName"], reference=REF_AUDIT,
     notes="TargetDomainName holds the caller computer name (the source host of the failed attempts).")
rule(17, "High", 4946, "Firewall exception rule added", "Defense evasion", SEC, P_AUDIT,
     ["RuleName", "RuleId", "ProfileChanged"], reference=REF_AUDIT,
     prerequisite="Audit MPSSVC Rule-Level Policy Change (Success).", false_positives=FP_UPDATES)
rule(18, "High", 4947, "Firewall exception rule modified", "Defense evasion", SEC, P_AUDIT,
     ["RuleName", "RuleId"], reference=REF_AUDIT,
     prerequisite="Audit MPSSVC Rule-Level Policy Change (Success).", false_positives=FP_UPDATES)
rule(19, "High", 4948, "Firewall exception rule deleted", "Defense evasion", SEC, P_AUDIT,
     ["RuleName", "RuleId"], reference=REF_AUDIT,
     prerequisite="Audit MPSSVC Rule-Level Policy Change (Success).", false_positives=FP_UPDATES)
rule(20, "High", 4950, "Firewall setting changed", "Defense evasion", SEC, P_AUDIT,
     ["SettingType", "SettingValue", "ProfileChanged"], reference=REF_AUDIT,
     prerequisite="Audit MPSSVC Rule-Level Policy Change (Success).",
     notes="Spreadsheet detail 'Setting' maps to SettingType/SettingValue. 4950 carries no SubjectUserName field.")
rule(21, "High", 5025, "Windows Firewall service stopped", "Defense evasion", SEC, P_AUDIT, [],
     reference=REF_OTHER_SYS, prerequisite="Audit Other System Events (Success).",
     notes="Channel verified: Security log (Audit Other System Events), not the Firewall With Advanced Security operational log.")
rule(22, "High", 6008, "Previous system shutdown was unexpected", "System stability", SYS, P_EVENTLOG_SYS,
     ["param1", "param2"], reference=REF_APPX_L,
     notes="Logged at the next boot; param1/param2 are the time and date of the unexpected shutdown. "
           "Renamed from 'Unexpected server shutdown' because it occurs on workstations too.",
     false_positives="Power loss, crashes and forced power-offs.")
rule(23, "High", 41, "Kernel-Power: reboot without clean shutdown", "System stability", SYS, P_KP,
     ["BugcheckCode", "BugcheckParameter1", "PowerButtonTimestamp"], reference=REF_KP,
     false_positives="Power loss, crashes, forced power-offs.")
rule(24, "High", 1100, "Event logging service shut down", "Defense evasion", SEC, P_EVENTLOG, [],
     reference=REF_EVENTLOG,
     notes="Provider verified: Microsoft-Windows-Eventlog writing to the Security log.",
     false_positives="Logged on every normal shutdown or restart; review alongside 4608/6005 at the next boot.")
rule(25, "Medium", 4699, "Scheduled task deleted", "Persistence", SEC, P_AUDIT,
     ["TaskName", "SubjectUserName"], reference=REF_AUDIT, prerequisite="Audit Other Object Access Events (Success).")
rule(26, "Medium", 4700, "Scheduled task enabled", "Persistence", SEC, P_AUDIT,
     ["TaskName", "SubjectUserName"], reference=REF_AUDIT, prerequisite="Audit Other Object Access Events (Success).")
rule(27, "Medium", 4701, "Scheduled task disabled", "Persistence", SEC, P_AUDIT,
     ["TaskName", "SubjectUserName"], reference=REF_AUDIT, prerequisite="Audit Other Object Access Events (Success).")
rule(28, "Medium", 4722, "User account enabled", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(29, "Medium", 4725, "User account disabled", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(30, "Medium", 4738, "User account changed", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName", "UserAccountControl", "PasswordLastSet"], reference=REF_AUDIT,
     notes="Changed attributes are the non-'-' values in the event data.")
rule(31, "Medium", 4781, "Account name changed", "Account management", SEC, P_AUDIT,
     ["OldTargetUserName", "NewTargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(32, "Medium", 4767, "User account unlocked", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(33, "Medium", 4731, "Local group created", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT,
     notes="Microsoft wording: 'A security-enabled local group was created.'")
rule(34, "Medium", 4733, "Member removed from local group", "Account management", SEC, P_AUDIT,
     ["MemberSid", "TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(35, "Medium", 4734, "Local group deleted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_AUDIT)
rule(36, "Medium", 4735, "Local group changed", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], reference=REF_APPX_L)
rule(37, "Medium", 4616, "System time changed", "Defense evasion", SEC, P_AUDIT,
     ["PreviousTime", "NewTime", "ProcessName", "SubjectUserName"], reference=REF_AUDIT,
     prerequisite="Audit Security State Change (Success).",
     false_positives="Windows Time service corrections and daylight/time-zone tooling.")
rule(38, "Medium", 6416, "New external device recognized", "Device monitoring", SEC, P_AUDIT,
     ["DeviceDescription", "ClassName", "DeviceId", "VendorIds"], reference=REF_AUDIT,
     prerequisite="Audit PNP Activity (Success).",
     notes="Category corrected from 'Data exfiltration' to 'Device monitoring' and '(USB)' dropped: 6416 fires for any Plug and Play device, "
           "and recognising a device is not evidence of exfiltration.")
rule(39, "Medium", 5142, "Network share created", "Lateral movement", SEC, P_AUDIT,
     ["ShareName", "ShareLocalPath", "SubjectUserName"], reference=REF_AUDIT,
     prerequisite="Audit File Share (Success).", notes="Spreadsheet detail 'SharePath' corresponds to ShareLocalPath.")
rule(40, "Medium", 5143, "Network share modified", "Lateral movement", SEC, P_AUDIT,
     ["ShareName", "ShareLocalPath", "SubjectUserName"], reference=REF_AUDIT, prerequisite="Audit File Share (Success).")
rule(41, "Medium", 5144, "Network share deleted", "Lateral movement", SEC, P_AUDIT,
     ["ShareName", "ShareLocalPath", "SubjectUserName"], reference=REF_AUDIT, prerequisite="Audit File Share (Success).")
rule(42, "Medium", 7040, "Service start type changed", "Persistence", SYS, P_SCM,
     ["param1", "param2", "param3", "param4"], reference=REF_SCM,
     false_positives="Very common during Windows Update (for example BITS and trusted installer services).")
rule(43, "Optional (Sysmon)", 8, "CreateRemoteThread", "Defense evasion", SYSMON, P_SYSMON,
     ["SourceImage", "TargetImage", "StartFunction"], reference=REF_SYSMON,
     prerequisite="Sysmon installed with a configuration that logs event 8.")
rule(44, "Optional (Sysmon)", 19, "WMI event filter", "Persistence", SYSMON, P_SYSMON,
     ["EventNamespace", "Name", "Query"], reference=REF_SYSMON, prerequisite="Sysmon with WmiEvent logging.")
rule(45, "Optional (Sysmon)", 20, "WMI event consumer", "Persistence", SYSMON, P_SYSMON,
     ["Name", "Type", "Destination"], reference=REF_SYSMON, prerequisite="Sysmon with WmiEvent logging.")
rule(46, "Optional (Sysmon)", 21, "WMI consumer bound to filter", "Persistence", SYSMON, P_SYSMON,
     ["Consumer", "Filter"], reference=REF_SYSMON, prerequisite="Sysmon with WmiEvent logging.")
rule(47, "Optional (Sysmon)", 25, "Process tampering", "Defense evasion", SYSMON, P_SYSMON,
     ["Image", "Type"], reference=REF_SYSMON, prerequisite="Sysmon 13+ with ProcessTampering logging.")

# ---------------------------------------------------------------- additions, enabled by default
N = None  # not a spreadsheet row
A = dict(origin="research")
P = dict(origin="prompt")          # named in the development prompt's candidate list
S = dict(origin="source-code")     # referenced in Griffendo's existing code (app.js / app.py)

# Authentication
rule(N, None, 4625, "Failed logon", "Authentication", SEC, P_AUDIT,
     ["TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "WorkstationName", "Status", "SubStatus"],
     severity="Low", **P, reference=REF_AUDIT, prerequisite="Audit Logon (Failure).",
     notes="A single failed logon. It does not by itself indicate brute force; repeated occurrences are each flagged.",
     false_positives="Mistyped passwords, stale saved credentials, services with expired passwords.")
rule(N, None, 4648, "Logon attempted with explicit credentials", "Authentication", SEC, P_AUDIT,
     ["SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName", "IpAddress"],
     severity="Low", **P, reference=REF_AUDIT, prerequisite="Audit Logon (Success).",
     false_positives="RunAs, mapped drives with alternate credentials, some scheduled tasks and services.")
rule(N, None, 4771, "Kerberos pre-authentication failed", "Authentication", SEC, P_AUDIT,
     ["TargetUserName", "IpAddress", "Status"], severity="Low", **P, reference=REF_AUDIT,
     prerequisite="Domain controllers only; Audit Kerberos Authentication Service (Failure).")
rule(N, None, 4649, "Replay attack detected", "Authentication", SEC, P_AUDIT,
     ["SubjectUserName", "TargetUserName", "WorkstationName"], severity="High", **A, reference=REF_APPX_L,
     notes="Microsoft rates High; may be a harmless false positive caused by misconfiguration.")
rule(N, None, 4964, "Special groups assigned to a new logon", "Privilege escalation", SEC, P_AUDIT,
     ["TargetUserName", "SidList"], severity="High", **A, reference=REF_APPX_L,
     prerequisite="Only generated when the Special Groups registry value is configured.")
rule(N, None, 4778, "Remote session reconnected", "Remote access", SEC, P_AUDIT,
     ["AccountName", "ClientName", "ClientAddress"], severity="Low", **P, reference=REF_AUDIT,
     prerequisite="Audit Other Logon/Logoff Events (Success).",
     notes="Microsoft wording: 'A session was reconnected to a Window Station.' Also logged for Fast User Switching.")
rule(N, None, 4779, "Remote session disconnected", "Remote access", SEC, P_AUDIT,
     ["AccountName", "ClientName", "ClientAddress"], severity="Low", **P, reference=REF_AUDIT,
     prerequisite="Audit Other Logon/Logoff Events (Success).")

# Account and privilege changes
rule(N, None, 4723, "Password change attempted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Low", **P, reference=REF_AUDIT,
     notes="The user changing their own password; 4724 is an administrator reset.")
rule(N, None, 4724, "Password reset attempted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **P, reference=REF_APPX_L)
rule(N, None, 4728, "Member added to security-enabled global group", "Privilege escalation", SEC, P_AUDIT,
     ["MemberName", "MemberSid", "TargetUserName", "SubjectUserName"], severity="High", **P, reference=REF_AUDIT)
rule(N, None, 4729, "Member removed from security-enabled global group", "Account management", SEC, P_AUDIT,
     ["MemberName", "MemberSid", "TargetUserName", "SubjectUserName"], severity="Medium", **P, reference=REF_AUDIT)
rule(N, None, 4732, "Member added to security-enabled local group", "Privilege escalation", SEC, P_AUDIT,
     ["MemberName", "MemberSid", "TargetUserName", "SubjectUserName"], severity="High", **P, reference=REF_AUDIT,
     notes="Covers additions to local Administrators, Remote Desktop Users and other local groups.")
rule(N, None, 4756, "Member added to security-enabled universal group", "Privilege escalation", SEC, P_AUDIT,
     ["MemberName", "MemberSid", "TargetUserName", "SubjectUserName"], severity="High", **P, reference=REF_AUDIT)
rule(N, None, 4757, "Member removed from security-enabled universal group", "Account management", SEC, P_AUDIT,
     ["MemberName", "MemberSid", "TargetUserName", "SubjectUserName"], severity="Medium", **P, reference=REF_AUDIT)
rule(N, None, 4737, "Security-enabled global group changed", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **P, reference=REF_APPX_L)
rule(N, None, 4727, "Security-enabled global group created", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_APPX_L,
     notes="Added for parity with spreadsheet rule 4731 (local group created).")
rule(N, None, 4730, "Security-enabled global group deleted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_AUDIT,
     notes="Parity with spreadsheet rule 4734.")
rule(N, None, 4754, "Security-enabled universal group created", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 4755, "Security-enabled universal group changed", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 4758, "Security-enabled universal group deleted", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_AUDIT)
rule(N, None, 4704, "User right assigned", "Privilege escalation", SEC, P_AUDIT,
     ["TargetSid", "PrivilegeList", "SubjectUserName"], severity="Medium", **P, reference=REF_AUDIT,
     prerequisite="Audit Authorization Policy Change (Success).", false_positives=FP_UPDATES)
rule(N, None, 4705, "User right removed", "Defense evasion", SEC, P_AUDIT,
     ["TargetSid", "PrivilegeList", "SubjectUserName"], severity="Medium", **P, reference=REF_AUDIT,
     prerequisite="Audit Authorization Policy Change (Success).", false_positives=FP_UPDATES)
rule(N, None, 4765, "SID History added to an account", "Privilege escalation", SEC, P_AUDIT,
     ["TargetUserName", "SourceUserName", "SidHistory"], severity="High", **A, reference=REF_APPX_L,
     prerequisite="Domain controllers.")
rule(N, None, 4766, "Attempt to add SID History failed", "Privilege escalation", SEC, P_AUDIT,
     ["TargetUserName", "SourceUserName"], severity="High", **A, reference=REF_APPX_L, prerequisite="Domain controllers.")
rule(N, None, 4794, "Attempt to set DSRM administrator password", "Credential access", SEC, P_AUDIT,
     ["SubjectUserName", "Workstation", "Status"], severity="High", **A, reference=REF_APPX_L, prerequisite="Domain controllers.")
rule(N, None, 4780, "ACL set on members of administrators groups", "Account management", SEC, P_AUDIT,
     ["TargetUserName", "SubjectUserName"], severity="Medium", **A, reference=REF_APPX_L,
     false_positives="SDProp (AdminSDHolder) on domain controllers.")
rule(N, None, 5376, "Credential Manager credentials backed up", "Credential access", SEC, P_AUDIT,
     ["SubjectUserName", "BackupFileName"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 5377, "Credential Manager credentials restored", "Credential access", SEC, P_AUDIT,
     ["SubjectUserName", "BackupFileName"], severity="Medium", **A, reference=REF_APPX_L)

# Policy and audit-integrity changes
rule(N, None, 4713, "Kerberos policy changed", "Policy change", SEC, P_AUDIT,
     ["SubjectUserName", "KerberosPolicyChange"], severity="Medium", **P, reference=REF_APPX_L,
     notes="Confirmed: Microsoft-Windows-Security-Auditing, Security log (Audit Authentication Policy Change).")
rule(N, None, 4739, "Domain policy changed", "Policy change", SEC, P_AUDIT,
     ["DomainPolicyChanged", "SubjectUserName"], severity="Medium", **S, reference=REF_APPX_L,
     notes="Found in Griffendo app.js (ACTIVITY_GROUPS 'Policy / audit changes').")
rule(N, None, 4706, "New trust created to a domain", "Policy change", SEC, P_AUDIT,
     ["TargetDomainName", "TrustType", "TrustDirection", "SubjectUserName"], severity="Medium", **A, reference=REF_APPX_L,
     prerequisite="Domain controllers.")
rule(N, None, 4715, "Audit policy (SACL) on an object changed", "Defense evasion", SEC, P_AUDIT,
     ["SubjectUserName", "OldSd", "NewSd"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 4906, "CrashOnAuditFail value changed", "Defense evasion", SEC, P_AUDIT,
     ["CrashOnAuditFailValue"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 4907, "Auditing settings on object changed", "Defense evasion", SEC, P_AUDIT,
     ["ObjectName", "ProcessName", "SubjectUserName", "OldSd", "NewSd"], severity="Low", **P, reference=REF_APPX_L,
     notes="Microsoft rates Medium; set to Low here because Windows servicing (TrustedInstaller) generates it in bulk during updates.",
     false_positives=FP_UPDATES)
rule(N, None, 4912, "Per-user audit policy changed", "Defense evasion", SEC, P_AUDIT,
     ["TargetUserSid", "CategoryId", "SubcategoryId", "AuditPolicyChanges"], severity="Medium", **A, reference=REF_APPX_L)
rule(N, None, 1101, "Audit events dropped by the transport", "Defense evasion", SEC, P_EVENTLOG,
     ["Reason"], severity="High", **P, reference=REF_EVENTLOG,
     notes="Security events were lost; the log has a gap.")
rule(N, None, 1104, "Security log is full", "Defense evasion", SEC, P_EVENTLOG, [], severity="Medium", **A,
     reference=REF_EVENTLOG, notes="New audit events may be lost or old ones overwritten.")

# Firewall / protection
rule(N, None, 4949, "Windows Firewall settings restored to defaults", "Defense evasion", SEC, P_AUDIT, [],
     severity="High", **A, reference=REF_AUDIT, prerequisite="Audit MPSSVC Rule-Level Policy Change (Success).")
rule(N, None, 5030, "Windows Firewall service failed to start", "Defense evasion", SEC, P_AUDIT, [],
     severity="Medium", **P, reference=REF_OTHER_SYS, prerequisite="Audit Other System Events.")
rule(N, None, 5034, "Windows Firewall driver stopped", "Defense evasion", SEC, P_AUDIT, [],
     severity="High", **P, reference=REF_OTHER_SYS, prerequisite="Audit Other System Events.",
     notes="Companion to spreadsheet rule 5025 (service stopped).")
rule(N, None, 5035, "Windows Firewall driver failed to start", "Defense evasion", SEC, P_AUDIT, [],
     severity="Medium", **P, reference=REF_OTHER_SYS, prerequisite="Audit Other System Events.")
rule(N, None, 5037, "Windows Firewall driver critical runtime error", "Defense evasion", SEC, P_AUDIT, [],
     severity="Medium", **P, reference=REF_OTHER_SYS, prerequisite="Audit Other System Events.")
rule(N, None, 5038, "Code integrity: invalid image hash", "Defense evasion", SEC, P_AUDIT,
     ["param1"], severity="Medium", **A, reference=REF_APPX_L, prerequisite="Audit System Integrity.")

# Object access (only produced where a SACL is configured, so volume is owner-controlled)
rule(N, None, 4657, "Registry value modified", "Object access", SEC, P_AUDIT,
     ["ObjectName", "ObjectValueName", "OldValue", "NewValue", "ProcessName", "SubjectUserName"],
     severity="Low", **P, reference=REF_AUDIT,
     prerequisite="Audit Registry (Success) and a SACL on the key; nothing is logged otherwise.")

# System / startup context
rule(N, None, 4608, "Windows starting up", "System stability", SEC, P_AUDIT, [], severity="Informational", **P,
     reference=REF_AUDIT, notes="Context for 41/6008/1100: marks each boot.")
rule(N, None, 4609, "Windows shutting down", "System stability", SEC, P_AUDIT, [], severity="Informational", **P,
     reference=REF_AUDIT, notes="Documented but rarely written on modern Windows; absence is not meaningful.")
rule(N, None, 6005, "Event Log service started", "System stability", SYS, P_EVENTLOG_SYS, [], severity="Informational", **P,
     reference=REF_EVENTLOG, notes="Effectively a boot marker.")
rule(N, None, 6006, "Event Log service stopped", "System stability", SYS, P_EVENTLOG_SYS, [], severity="Informational", **P,
     reference=REF_EVENTLOG, notes="Logged on clean shutdown.")
rule(N, None, 1074, "Shutdown or restart initiated by a process or user", "System stability", SYS, P_USER32,
     ["param1", "param2", "param3", "param5", "param7"], severity="Low", **P, reference=REF_EVENTLOG,
     notes="Shows the initiating process (param1), reason (param3) and user (param7).")
rule(N, None, 7031, "Service terminated unexpectedly (recovery action)", "System stability", SYS, P_SCM,
     ["param1", "param2", "param5"], severity="Low", **P, reference=REF_SCM)
rule(N, None, 7034, "Service terminated unexpectedly", "System stability", SYS, P_SCM,
     ["param1", "param2"], severity="Low", **P, reference=REF_SCM,
     notes="Found in Griffendo app.js ('Services' activity group).")

# Defender additions (same channel as spreadsheet rows 6-10)
rule(N, None, 1006, "Malware found by scan (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Path", "Process Name"], severity="Critical", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_MALWARE_DETECTED (engine/scan detection; 1116 is the platform state event).")
rule(N, None, 1015, "Suspicious behavior detected (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Path", "Process Name"], severity="High", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_BEHAVIOR_DETECTED.")
rule(N, None, 1118, "Malware remediation failed (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Action Name", "Error Description", "Path"], severity="Critical", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_STATE_MALWARE_ACTION_FAILED: the threat may still be active.")
rule(N, None, 1119, "Malware remediation critically failed (Defender)", "Malware", DEF, P_DEF,
     ["Threat Name", "Action Name", "Error Description", "Path"], severity="Critical", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_STATE_MALWARE_ACTION_CRITICALLY_FAILED.")
rule(N, None, 1121, "Attack surface reduction rule blocked an action", "Malware", DEF, P_DEF,
     ["ID", "Path", "Process Name"], severity="High", **A,
     reference="Microsoft Learn - Attack surface reduction rules reference (event 1121 = block mode)",
     verification="Verified against Microsoft documentation (ASR reference); not re-fetched this session",
     notes="Block-mode ASR events only; audit-mode 1122 is not included.")
rule(N, None, 5004, "Defender real-time protection configuration changed", "Defense evasion", DEF, P_DEF,
     ["Feature Name", "Configuration"], severity="Medium", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_RTP_FEATURE_CONFIGURED.")
rule(N, None, 5007, "Defender configuration changed", "Defense evasion", DEF, P_DEF,
     ["Old Value", "New Value"], severity="Medium", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_CONFIG_CHANGED: includes new exclusions and disabled features.",
     false_positives="Policy refreshes and platform updates also change configuration.")
rule(N, None, 5008, "Defender engine failure", "Defense evasion", DEF, P_DEF,
     ["Resource", "Failure Type", "Exception Code"], severity="Medium", **A, reference=REF_DEF,
     notes="MALWAREPROTECTION_ENGINE_FAILURE.")
rule(N, None, 5013, "Defender tamper protection blocked a change", "Defense evasion", DEF, P_DEF,
     ["Value"], severity="High", **A,
     reference="Microsoft Learn - Microsoft Defender tamper protection",
     verification="Verified against Microsoft documentation (tamper protection); not re-fetched this session")

# Task Scheduler operational log (alternative source when Security object-access auditing is off)
rule(N, None, 106, "Scheduled task registered (Task Scheduler log)", "Persistence", TASK, P_TASK,
     ["TaskName", "UserContext"], severity="High", **P, reference=REF_TASK,
     prerequisite="Task Scheduler Operational log enabled ('Enable All Tasks History'); it is disabled by default on many Windows versions.",
     notes="Same action as Security 4698. When both sources are on, one task creation produces two detections (different events).")
rule(N, None, 140, "Scheduled task updated (Task Scheduler log)", "Persistence", TASK, P_TASK,
     ["TaskName", "UserName"], severity="High", **P, reference=REF_TASK,
     prerequisite="Task Scheduler Operational log enabled.", notes="Same action as Security 4702.")
rule(N, None, 141, "Scheduled task deleted (Task Scheduler log)", "Persistence", TASK, P_TASK,
     ["TaskName", "UserName"], severity="Medium", **P, reference=REF_TASK,
     prerequisite="Task Scheduler Operational log enabled.", notes="Same action as Security 4699.")

# RDP
rule(N, None, 1149, "RDP network authentication succeeded", "Remote access", RDP, P_RDP,
     ["Param1", "Param2", "Param3"], severity="Low", **A, reference=REF_RDP,
     notes="Param1 user, Param2 domain, Param3 source address. Records a successful network-level RDP authentication, "
           "not proof of an interactive logon. Listed in the spreadsheet's removed events; re-added because it is "
           "directly meaningful for remote-access review.")

# Sysmon additions
rule(N, None, 4, "Sysmon service state changed", "Defense evasion", SYSMON, P_SYSMON, ["State", "Version"],
     severity="Optional", **A, reference=REF_SYSMON, notes="Reveals Sysmon being stopped.")
rule(N, None, 16, "Sysmon configuration changed", "Defense evasion", SYSMON, P_SYSMON, ["Configuration", "ConfigurationFileHash"],
     severity="Optional", **A, reference=REF_SYSMON, notes="Sysmon 'ServiceConfigurationChange'.")
rule(N, None, 9, "Raw disk read (RawAccessRead)", "Credential access", SYSMON, P_SYSMON, ["Image", "Device"],
     severity="Optional", **A, reference=REF_SYSMON, notes="Used to copy locked files such as NTDS.dit or SAM.")
rule(N, None, 27, "Sysmon blocked executable file creation", "Defense evasion", SYSMON, P_SYSMON, ["Image", "TargetFilename"],
     severity="Optional", **A, reference=REF_SYSMON, prerequisite="Sysmon 14+ with FileBlockExecutable rules.")
rule(N, None, 28, "Sysmon blocked file shredding", "Defense evasion", SYSMON, P_SYSMON, ["Image", "TargetFilename"],
     severity="Optional", **A, reference=REF_SYSMON, prerequisite="Sysmon 14.1+ with FileBlockShredding rules.")

# ---------------------------------------------------------------- catalogued but disabled by default
D = "Disabled by default: routine high-volume activity that would bury the other detections. Enable it in the catalog to flag every occurrence."
rule(N, None, 4624, "Successful logon", "Authentication", SEC, P_AUDIT,
     ["TargetUserName", "LogonType", "IpAddress", "WorkstationName", "LogonProcessName"], severity="Informational",
     enabled=False, **P, reference=REF_AUDIT, notes=D + " Not every 4624 is RDP; LogonType 10 is RemoteInteractive.")
rule(N, None, 4672, "Special privileges assigned to new logon", "Privilege escalation", SEC, P_AUDIT,
     ["SubjectUserName", "PrivilegeList"], severity="Informational", enabled=False, **P, reference=REF_AUDIT, notes=D)
rule(N, None, 4688, "Process created", "Execution", SEC, P_AUDIT,
     ["NewProcessName", "CommandLine", "ParentProcessName", "SubjectUserName"], severity="Informational",
     enabled=False, **P, reference=REF_AUDIT, notes=D)
rule(N, None, 4768, "Kerberos TGT requested", "Authentication", SEC, P_AUDIT, ["TargetUserName", "IpAddress", "Status"],
     severity="Informational", enabled=False, **P, reference=REF_AUDIT, notes=D + " Domain controllers only.")
rule(N, None, 4769, "Kerberos service ticket requested", "Authentication", SEC, P_AUDIT,
     ["TargetUserName", "ServiceName", "TicketEncryptionType", "IpAddress"], severity="Informational",
     enabled=False, **P, reference=REF_AUDIT, notes=D + " Domain controllers only.")
rule(N, None, 4776, "NTLM credential validation", "Authentication", SEC, P_AUDIT, ["TargetUserName", "Workstation", "Status"],
     severity="Informational", enabled=False, **P, reference=REF_AUDIT, notes=D)
rule(N, None, 4656, "Handle to an object requested", "Object access", SEC, P_AUDIT, ["ObjectName", "ProcessName", "AccessList"],
     severity="Informational", enabled=False, **P, reference=REF_AUDIT, notes=D + " Requires SACLs.")
rule(N, None, 4663, "Object access attempted", "Object access", SEC, P_AUDIT, ["ObjectName", "ProcessName", "AccessList"],
     severity="Informational", enabled=False, **P, reference=REF_AUDIT, notes=D + " Requires SACLs.")
rule(N, None, 4660, "Object deleted", "Object access", SEC, P_AUDIT, ["ProcessName", "SubjectUserName"],
     severity="Low", enabled=False, **P, reference=REF_AUDIT, notes=D + " Pairs with 4663, which carries the object name.")
rule(N, None, 4670, "Permissions on an object changed", "Object access", SEC, P_AUDIT, ["ObjectName", "ProcessName", "OldSd", "NewSd"],
     severity="Low", enabled=False, **P, reference=REF_AUDIT, notes=D)
rule(N, None, 4798, "Local group membership of a user enumerated", "Discovery", SEC, P_AUDIT, ["TargetUserName", "CallerProcessName"],
     severity="Low", enabled=False, **A, reference=REF_AUDIT, notes=D + " Listed in the spreadsheet's removed events.")
rule(N, None, 4799, "Members of a security-enabled local group enumerated", "Discovery", SEC, P_AUDIT,
     ["TargetUserName", "CallerProcessName"], severity="Low", enabled=False, **A, reference=REF_AUDIT,
     notes=D + " Listed in the spreadsheet's removed events.")
rule(N, None, 5140, "Network share accessed", "Lateral movement", SEC, P_AUDIT, ["ShareName", "IpAddress", "SubjectUserName"],
     severity="Informational", enabled=False, **A, reference=REF_AUDIT, notes=D + " Listed in the spreadsheet's removed events.")
rule(N, None, 5145, "Network share object access checked", "Lateral movement", SEC, P_AUDIT,
     ["ShareName", "RelativeTargetName", "IpAddress"], severity="Informational", enabled=False, **A, reference=REF_AUDIT,
     notes=D + " Listed in the spreadsheet's removed events.")
rule(N, None, 5156, "Windows Filtering Platform allowed a connection", "Network activity", SEC, P_AUDIT,
     ["Application", "SourceAddress", "DestAddress", "DestPort"], severity="Informational", enabled=False, **S,
     reference=REF_APPX_L, notes=D + " Found in Griffendo app.js ('Network / firewall').")
rule(N, None, 5157, "Windows Filtering Platform blocked a connection", "Network activity", SEC, P_AUDIT,
     ["Application", "SourceAddress", "DestAddress", "DestPort"], severity="Low", enabled=False, **S,
     reference=REF_APPX_L, notes=D + " Found in Griffendo app.js ('Network / firewall').")
rule(N, None, 4103, "PowerShell pipeline execution (module logging)", "Execution", PS, P_PS, ["Payload", "ContextInfo"],
     severity="Informational", enabled=False, **P, reference=REF_PS, notes=D + " Requires PowerShell module logging.")
rule(N, None, 4104, "PowerShell script block logged", "Execution", PS, P_PS, ["ScriptBlockText", "Path"],
     severity="Low", enabled=False, **P, reference=REF_PS,
     notes=D + " With script block logging on, every script block is logged. Without it, Windows still logs blocks it "
           "considers suspicious, but matching on the ID alone cannot tell those apart.")

# ---------------------------------------------------------------- reviewed, not included
REVIEWED_NOT_INCLUDED = [
    {"event_id": 3003, "channel": "(unresolved)", "found_in": "Original sample list (spreadsheet Notes)",
     "reason": "Could not be matched to an authoritative shutdown event on any standard channel. Not treated as a shutdown event."},
    {"event_id": 4689, "channel": SEC, "found_in": "Prompt; app.js ACTIVITY_GROUPS",
     "reason": "Process termination is routine and has no anomaly meaning on its own."},
    {"event_id": 4634, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS", "reason": "Logoff; routine."},
    {"event_id": 4647, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS", "reason": "User-initiated logoff; routine."},
    {"event_id": 4673, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "Privileged service called; extremely high volume (Audit Sensitive Privilege Use)."},
    {"event_id": 4674, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "Operation on privileged object; extremely high volume."},
    {"event_id": 4902, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "Per-user audit policy table created; logged at every boot."},
    {"event_id": 4904, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "Security event source registration; routine at service start."},
    {"event_id": 7035, "channel": SYS, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "Service control request sent; routine (legacy event)."},
    {"event_id": 7036, "channel": SYS, "found_in": "app.py EVENT_LABELS; app.js ACTIVITY_GROUPS",
     "reason": "Service entered running/stopped state; very high routine volume."},
    {"event_id": 5158, "channel": SEC, "found_in": "app.js ACTIVITY_GROUPS",
     "reason": "WFP permitted bind to a local port; very high volume, no anomaly meaning."},
    {"event_id": 1, "channel": SYSMON, "found_in": "app.js ACTIVITY_GROUPS ('Process execution')",
     "reason": "Sysmon process creation; telemetry volume. Note that ID 1 in the System log is a different event "
               "(several providers use it), which is why rules are keyed on channel + ID."},
    {"event_id": 3, "channel": SYSMON, "found_in": "app.js ACTIVITY_GROUPS ('Network / firewall')",
     "reason": "Sysmon network connection; telemetry volume."},
    {"event_id": 5, "channel": SYSMON, "found_in": "app.js ACTIVITY_GROUPS", "reason": "Sysmon process terminated; telemetry."},
    {"event_id": 1, "channel": SYS, "found_in": "Research (Kernel-General time change)",
     "reason": "ID 1 in the System log is shared by several providers (Kernel-General, Power-Troubleshooter and others); "
               "an ID-only rule would mislabel events. 4616 covers time changes."},
    {"event_id": 4618, "channel": SEC, "found_in": "Research (Appendix L, High)",
     "reason": "Only generated by a specific monitored-pattern configuration; add if your environment uses it."},
    {"event_id": 4621, "channel": SEC, "found_in": "Research (Appendix L, Medium)",
     "reason": "Only relevant where CrashOnAuditFail is configured; 4906 covers changes to that setting."},
    {"event_id": 4692, "channel": SEC, "found_in": "Research (Appendix L, Medium)",
     "reason": "DPAPI master-key backup is routine in domains (automatic backup to a DC)."},
    {"event_id": 4741, "channel": SEC, "found_in": "Research", "reason": "Computer account created; routine domain join noise."},
    {"event_id": 5027, "channel": SEC, "found_in": "Research (Audit Other System Events)",
     "reason": "Firewall policy read/parse errors (5027-5029) are operational faults; 5025/5030/5034 cover protection being down."},
    {"event_id": 4954, "channel": SEC, "found_in": "Research", "reason": "Group Policy firewall refresh; routine."},
    {"event_id": 1122, "channel": DEF, "found_in": "Research",
     "reason": "ASR audit-mode event; organisations running ASR in audit mode generate large volumes. 1121 (block) is included."},
    {"event_id": 5860, "channel": WMI, "found_in": "Research",
     "reason": "Temporary WMI event registrations are created constantly by management software."},
    {"event_id": 6281, "channel": SEC, "found_in": "Research",
     "reason": "Code integrity page-hash failures are frequent for some legitimate drivers; 5038 is included."},
    {"event_id": 6, "channel": SYSMON, "found_in": "Research", "reason": "Driver loaded; noisy unless the Sysmon config filters it."},
    {"event_id": 10, "channel": SYSMON, "found_in": "Research", "reason": "ProcessAccess; volume depends entirely on Sysmon config."},
    {"event_id": 29, "channel": SYSMON, "found_in": "Research", "reason": "FileExecutableDetected; noisy on build/dev hosts."},
]


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "catalog" / "anomaly_catalog.json")
    keys = [(r["channel"].lower(), r["event_id"]) for r in rules]
    duplicates = {k for k in keys if keys.count(k) > 1}
    if duplicates:
        raise SystemExit(f"duplicate channel/event rules: {sorted(duplicates)}")
    ids = [r["rule_id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate rule ids")
    rows = sorted(r["spreadsheet_row"] for r in rules if r["spreadsheet_row"])
    if rows != list(range(1, 48)):
        raise SystemExit("spreadsheet rows 1-47 must each appear exactly once")
    catalog = {
        "catalog_version": CATALOG_VERSION,
        "description": "Griffendo anomaly catalog. An event whose channel and Event ID match an enabled rule, "
                       "and whose time falls in the analysis window, is flagged. No other field is checked.",
        "window_days": 7,
        "severity_order": ["Critical", "High", "Medium", "Low", "Informational", "Optional"],
        "rules": rules,
        "reviewed_not_included": REVIEWED_NOT_INCLUDED,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    enabled = sum(r["enabled"] for r in rules)
    print(f"wrote {out}: {len(rules)} rules ({enabled} enabled, {len(rules) - enabled} disabled), "
          f"{len(REVIEWED_NOT_INCLUDED)} reviewed-not-included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
