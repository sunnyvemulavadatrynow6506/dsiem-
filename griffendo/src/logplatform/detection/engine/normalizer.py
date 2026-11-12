"""Stored event -> normalized event (see schema.py for the field names).

Input is a stored event row (the ``events`` table): its parsed ``normalized_json``
(EventData fields + System values extracted at ingest) plus a few columns.  Raw
XML is never re-parsed here, except for events stored by v4 or older builds,
which lack the System Keywords/Task/Execution values; for those the values are
read from the stored XML with one small regular expression (``raw_fallback``).

Rules:
  * a field is set only when the event carries a meaningful value (``-``, ``n/a``,
    ``0x0`` placeholders are treated as absent, as in the v2 parser);
  * nothing is invented: derived fields (``process.name`` from a path,
    ``process.args`` from a command line, ``registry.value`` from a registry path,
    ``dll.code_signature.trusted`` from Sysmon's SignatureStatus) are documented
    derivations of values that are present in the event;
  * the original EventData stays available as ``winlog.event_data.<Name>``
    (case-insensitive lookup) for every event.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import schema

PLACEHOLDERS = {"", "-", "--", "n/a", "(null)", "null", "none", "unknown"}
_ID_PLACEHOLDERS = PLACEHOLDERS | {"0x0", "0x00000000", "0"}
LOGON_TYPES = {
    "0": "System", "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
    "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive",
    "12": "CachedRemoteInteractive", "13": "CachedUnlock",
}
# Security events whose *target* account is the account the event is about (logon-type events).
LOGON_TARGET = {4624, 4625, 4634, 4647, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 4964, 4672}
GROUP_EVENTS = {4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764,
                4799}
# event.action names for Security events (the names the Elastic/Winlogbeat security module uses).
SECURITY_ACTIONS = {
    1100: "logging-service-shutdown", 1102: "audit-log-cleared", 1104: "logging-full", 4624: "logged-in",
    4625: "logon-failed", 4634: "logged-out", 4647: "logged-out", 4648: "logged-in-explicit",
    4672: "logged-in-special", 4688: "created-process", 4689: "exited-process", 4697: "service-installed",
    4698: "scheduled-task-created", 4699: "scheduled-task-deleted", 4700: "scheduled-task-enabled",
    4701: "scheduled-task-disabled", 4702: "scheduled-task-updated", 4719: "changed-audit-config",
    4720: "added-user-account", 4722: "enabled-user-account", 4723: "changed-password", 4724: "reset-password",
    4725: "disabled-user-account", 4726: "deleted-user-account", 4727: "added-group-account",
    4728: "added-member-to-group", 4729: "removed-member-from-group", 4730: "deleted-group-account",
    4731: "added-group-account", 4732: "added-member-to-group", 4733: "removed-member-from-group",
    4734: "deleted-group-account", 4735: "modified-group-account", 4737: "modified-group-account",
    4738: "modified-user-account", 4740: "locked-out-user-account", 4741: "added-computer-account",
    4742: "changed-computer-account", 4743: "deleted-computer-account", 4754: "added-group-account",
    4755: "modified-group-account", 4756: "added-member-to-group", 4757: "removed-member-from-group",
    4758: "deleted-group-account", 4767: "unlocked-user-account", 4768: "kerberos-authentication-ticket-requested",
    4769: "kerberos-service-ticket-requested", 4770: "kerberos-service-ticket-renewed",
    4771: "kerberos-preauth-failed", 4776: "credential-validated", 4778: "session-reconnected",
    4779: "session-disconnected", 4781: "renamed-user-account", 4798: "group-membership-enumerated",
    4799: "user-member-enumerated", 4964: "logged-in-special", 4703: "Token Right Adjusted Events", 5024: "firewall-service-started",
    5025: "firewall-service-stopped",
}
SECURITY_CATEGORY = {
    **{eid: (["authentication"], ["start"]) for eid in (4624, 4648, 4672, 4768, 4769, 4770, 4776, 4778, 4964)},
    **{eid: (["authentication"], ["start"]) for eid in (4625, 4771)},
    **{eid: (["authentication"], ["end"]) for eid in (4634, 4647, 4779)},
    **{eid: (["iam"], ["user", "creation"]) for eid in (4720, 4741)},
    **{eid: (["iam"], ["user", "change"]) for eid in (4722, 4723, 4724, 4725, 4738, 4740, 4742, 4767, 4781)},
    **{eid: (["iam"], ["user", "deletion"]) for eid in (4726, 4743)},
    **{eid: (["iam"], ["group", "creation"]) for eid in (4727, 4731, 4754)},
    **{eid: (["iam"], ["group", "change"]) for eid in (4728, 4729, 4732, 4733, 4735, 4737, 4755, 4756, 4757)},
    **{eid: (["iam"], ["group", "deletion"]) for eid in (4730, 4734, 4758)},
    **{eid: (["configuration"], ["change"]) for eid in (4697, 4698, 4699, 4700, 4701, 4702, 4719, 4739, 4904, 4905,
                                                     4906, 4907, 4946, 4947, 4948, 4950, 1102, 1100)},
    **{eid: (["iam"], ["info"]) for eid in (4798, 4799)},
}
_AUDIT_SUCCESS = 0x20000000000000
_AUDIT_FAILURE = 0x10000000000000
_SEVERITY_VALUE = {"1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFORMATION", "0": "INFORMATION",
                   "5": "VERBOSE"}
_LEVEL_NAMES = {"Critical": "1", "Error": "2", "Warning": "3", "Informational": "4", "Verbose": "5"}
_SYSTEM_RE = re.compile(r"<(Keywords|Task|Opcode|Level)>([^<]*)</\1>|<Execution\s+ProcessID=['\"](\d+)['\"]"
                        r"(?:\s+ThreadID=['\"](\d+)['\"])?|<Security\s+UserID=['\"]([^'\"]+)['\"]")
_HASH_RE = re.compile(r"(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)")
_DWORD_RE = re.compile(r"^(DWORD|QWORD) \(0x([0-9a-fA-F]+)\)$")
HIVES = {"HKLM": "HKLM", "HKU": "HKU", "HKCR": "HKCR", "HKCU": "HKCU", "HKCC": "HKCC",
         "\\REGISTRY\\MACHINE": "HKLM", "\\REGISTRY\\USER": "HKU"}


def meaningful(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() not in PLACEHOLDERS


def base_name(path: str | None) -> str | None:
    if not meaningful(path):
        return None
    text = path.strip().strip('"').rstrip("\\/ ")
    name = text.replace("/", "\\").rsplit("\\", 1)[-1].strip()
    return name or None


def directory(path: str) -> str | None:
    text = path.strip().strip('"').replace("/", "\\")
    return text.rsplit("\\", 1)[0] if "\\" in text else None


def extension(name: str | None) -> str | None:
    if not name or "." not in name:
        return None
    ext = name.rsplit(".", 1)[-1]
    return ext or None


def split_command_line(command: str) -> list[str]:
    """Windows CommandLineToArgvW splitting (the same rules Windows uses to build argv)."""
    args: list[str] = []
    text = command.strip()
    if not text:
        return args
    i, n = 0, len(text)
    # argv[0]: quoted -> up to the next quote, no escapes; otherwise up to whitespace.
    if text[0] == '"':
        end = text.find('"', 1)
        if end == -1:
            return [text[1:]]
        args.append(text[1:end])
        i = end + 1
    else:
        while i < n and text[i] not in " \t":
            i += 1
        args.append(text[:i])
    while True:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        current: list[str] = []
        quoted = False
        while i < n:
            ch = text[i]
            if ch == "\\":
                start = i
                while i < n and text[i] == "\\":
                    i += 1
                count = i - start
                if i < n and text[i] == '"':
                    current.append("\\" * (count // 2))
                    if count % 2:
                        current.append('"')
                        i += 1
                    continue
                current.append("\\" * count)
                continue
            if ch == '"':
                if quoted and i + 1 < n and text[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                quoted = not quoted
                i += 1
                continue
            if ch in " \t" and not quoted:
                break
            current.append(ch)
            i += 1
        args.append("".join(current))
    return args


def _int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower() in _ID_PLACEHOLDERS and text != "0":
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _system_values(stored: dict[str, Any], raw_fallback: str | None) -> dict[str, str]:
    system = stored.get("system")
    if isinstance(system, dict):
        return system
    values: dict[str, str] = {}
    if raw_fallback:
        head = raw_fallback.split("</System>", 1)[0]
        for match in _SYSTEM_RE.finditer(head):
            if match.group(1):
                values[match.group(1).lower()] = match.group(2).strip()
            elif match.group(3):
                values["process_id"] = match.group(3)
                if match.group(4):
                    values["thread_id"] = match.group(4)
            elif match.group(5):
                values["user_id"] = match.group(5)
    return values


class Lookup:
    """Case-insensitive access to the raw EventData of one event."""

    __slots__ = ("raw", "lower")

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.lower = {str(key).lower(): value for key, value in raw.items()}

    def get(self, *names: str) -> str | None:
        for name in names:
            value = self.lower.get(name.lower())
            if meaningful(value):
                return value.strip()
        return None


def _set(ev: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, str) and not meaningful(value):
        return
    ev[key] = value


def _process(ev: dict[str, Any], prefix: str, path: str | None, command: str | None = None,
             pid: Any = None, guid: str | None = None) -> None:
    if meaningful(path):
        clean = path.strip().strip('"')
        ev[f"{prefix}.executable"] = clean
        name = base_name(clean)
        if name:
            ev[f"{prefix}.name"] = name
    if meaningful(command):
        ev[f"{prefix}.command_line"] = command
        args = split_command_line(command)
        ev[f"{prefix}.args"] = args
        ev[f"{prefix}.args_count"] = len(args)
    pid_value = _int(pid)
    if pid_value is not None:
        ev[f"{prefix}.pid"] = pid_value
    if meaningful(guid):
        ev[f"{prefix}.entity_id"] = guid.strip().strip("{}").lower()


def _user(ev: dict[str, Any], account: str | None, prefix: str = "user") -> None:
    if not meaningful(account):
        return
    text = account.strip()
    if "\\" in text:
        domain, name = text.split("\\", 1)
        _set(ev, f"{prefix}.domain", domain)
        _set(ev, f"{prefix}.name", name)
    else:
        _set(ev, f"{prefix}.name", text)


def _hashes(ev: dict[str, Any], prefix: str, value: str | None) -> None:
    if not value:
        return
    for algorithm, digest in _HASH_RE.findall(value):
        key = "imphash" if algorithm.upper() == "IMPHASH" else algorithm.lower()
        target = f"{prefix.replace('.hash', '.pe')}.imphash" if key == "imphash" else f"{prefix}.{key}"
        ev[target] = digest.lower()


def _file(ev: dict[str, Any], path: str | None) -> None:
    if not meaningful(path):
        return
    clean = path.strip()
    ev["file.path"] = clean
    name = base_name(clean)
    if name:
        ev["file.name"] = name
        ext = extension(name)
        if ext:
            ev["file.extension"] = ext
    folder = directory(clean)
    if folder:
        ev["file.directory"] = folder


def _registry(ev: dict[str, Any], f: Lookup, sysmon_event: int) -> None:
    target = f.get("TargetObject")
    if not target:
        return
    ev["registry.path"] = target
    head = target.split("\\", 1)[0].upper()
    hive = HIVES.get(head)
    rest = target.split("\\", 1)[1] if "\\" in target else ""
    if hive:
        ev["registry.hive"] = hive
    event_type = (f.get("EventType") or "").lower()
    if event_type in ("setvalue", "deletevalue") or sysmon_event == 13:
        if "\\" in rest:
            ev["registry.key"] = rest.rsplit("\\", 1)[0]
        ev["registry.value"] = target.rsplit("\\", 1)[-1]
    else:
        ev["registry.key"] = rest
    details = f.lower.get("details")
    if isinstance(details, str) and details.strip() != "":
        match = _DWORD_RE.match(details.strip())
        if match:
            ev["registry.data.strings"] = [str(int(match.group(2), 16))]
            ev["registry.data.type"] = "REG_" + match.group(1)
        else:
            ev["registry.data.strings"] = [details]
            if details.startswith("Binary Data"):
                ev["registry.data.type"] = "REG_BINARY"
    if event_type == "createkey":
        ev["event.type"] = ["creation"]
    elif event_type.startswith("delete"):
        ev["event.type"] = ["deletion"]
    else:
        ev["event.type"] = ["change"]
    action = {12: "Registry object added or deleted (rule: RegistryEvent)", 13: "Registry value set (rule: RegistryEvent)",
              14: "Registry object renamed (rule: RegistryEvent)"}.get(sysmon_event)
    if action:
        ev["event.action"] = action


def _sysmon(ev: dict[str, Any], eid: int, f: Lookup) -> None:
    key = schema.source_key(schema.SYSMON, eid)
    source = schema.SOURCES.get(key)
    if source:
        ev["event.category"] = list(source["ecs"]["event.category"])
        ev["event.type"] = [source["ecs"]["event.type"][0]]
        if source["ecs"]["event.action"]:
            ev["event.action"] = source["ecs"]["event.action"][0]
    _user(ev, f.get("User"))
    if eid in (8, 10):
        _process(ev, "process", f.get("SourceImage"), pid=f.get("SourceProcessId"), guid=f.get("SourceProcessGuid"))
        _user(ev, f.get("SourceUser"))
        target = f.get("TargetImage")
        if target:
            ev["process.target.executable"] = target
            _set(ev, "process.target.name", base_name(target))
        tpid = _int(f.get("TargetProcessId"))
        if tpid is not None:
            ev["process.target.pid"] = tpid
        return
    _process(ev, "process", f.get("Image"), f.get("CommandLine"), f.get("ProcessId"), f.get("ProcessGuid"))
    if eid == 1:
        _process(ev, "process.parent", f.get("ParentImage"), f.get("ParentCommandLine"), f.get("ParentProcessId"),
                 f.get("ParentProcessGuid"))
        _set(ev, "process.working_directory", f.get("CurrentDirectory"))
        for source_name, target in (("OriginalFileName", "original_file_name"), ("Description", "description"),
                                    ("Product", "product"), ("Company", "company"), ("FileVersion", "file_version")):
            _set(ev, f"process.pe.{target}", f.get(source_name))
        _hashes(ev, "process.hash", f.get("Hashes"))
        _set(ev, "winlog.logon.id", f.get("LogonId"))
        _set(ev, "process.integrity_level", f.get("IntegrityLevel"))
    elif eid == 5:
        _set(ev, "winlog.logon.id", f.get("LogonId"))
    elif eid == 3:
        _set(ev, "network.transport", (f.get("Protocol") or "").lower() or None)
        initiated = (f.get("Initiated") or "").lower()
        if initiated in ("true", "false"):
            ev["network.direction"] = "egress" if initiated == "true" else "ingress"
        _set(ev, "network.type", "ipv6" if (f.get("SourceIsIpv6") or "").lower() == "true" else
             ("ipv4" if f.get("SourceIsIpv6") else None))
        _set(ev, "source.ip", f.get("SourceIp"))
        port = _int(f.get("SourcePort"))
        if port is not None:
            ev["source.port"] = port
        _set(ev, "source.domain", f.get("SourceHostname"))
        _set(ev, "destination.ip", f.get("DestinationIp"))
        port = _int(f.get("DestinationPort"))
        if port is not None:
            ev["destination.port"] = port
        _set(ev, "destination.domain", f.get("DestinationHostname"))
    elif eid == 22:
        _set(ev, "dns.question.name", f.get("QueryName"))
        results = f.get("QueryResults")
        if results:
            answers = [item.strip() for item in results.split(";") if item.strip()]
            ev["dns.answers.data"] = answers
            ips = [item.removeprefix("::ffff:") for item in answers if re.match(r"^[0-9a-fA-F:.]+$", item.removeprefix("::ffff:"))]
            if ips:
                ev["dns.resolved_ip"] = ips
        ev["network.protocol"] = "dns"
    elif eid in (7, 6):
        loaded = f.get("ImageLoaded")
        if loaded:
            if eid == 7:
                ev["dll.path"] = loaded
                _set(ev, "dll.name", base_name(loaded))
                ev["file.path"] = loaded
                _set(ev, "file.name", base_name(loaded))
            else:
                _file(ev, loaded)
        prefixes = ("dll", "file") if eid == 7 else ("file",)
        if eid == 7:
            for source_name, target in (("OriginalFileName", "original_file_name"), ("Description", "description"),
                                        ("Product", "product"), ("Company", "company"), ("FileVersion", "file_version")):
                for pre in prefixes:
                    _set(ev, f"{pre}.pe.{target}", f.get(source_name))
        signed = (f.get("Signed") or "").lower()
        status = f.get("SignatureStatus")
        for pre in prefixes:
            _hashes(ev, f"{pre}.hash", f.get("Hashes"))
            if signed in ("true", "false"):
                ev[f"{pre}.code_signature.exists"] = signed == "true"
            _set(ev, f"{pre}.code_signature.subject_name", f.get("Signature"))
            _set(ev, f"{pre}.code_signature.status", status)
            if signed in ("true", "false") and status:
                # Sysmon's SignatureStatus is the WinVerifyTrust result: "Valid" means the chain is trusted.
                ev[f"{pre}.code_signature.trusted"] = signed == "true" and status.lower() == "valid"
    elif eid in (11, 2, 15, 23, 26, 29):
        _file(ev, f.get("TargetFilename"))
        _hashes(ev, "file.hash", f.get("Hashes") or f.get("Hash"))
    elif eid in (12, 13, 14):
        _registry(ev, f, eid)
    elif eid in (17, 18):
        _set(ev, "file.name", f.get("PipeName"))


def _security(ev: dict[str, Any], eid: int, f: Lookup) -> None:
    action = SECURITY_ACTIONS.get(eid)
    if action:
        ev["event.action"] = action
    category = SECURITY_CATEGORY.get(eid)
    if category:
        ev["event.category"], ev["event.type"] = list(category[0]), list(category[1])
    if eid in (4688, 4689):
        ev["event.category"] = ["process"]
        ev["event.type"] = ["start", "process_start"] if eid == 4688 else ["end"]
        new_name = f.get("NewProcessName") if eid == 4688 else f.get("ProcessName")
        new_pid = f.get("NewProcessId") if eid == 4688 else f.get("ProcessId")
        _process(ev, "process", new_name, f.get("CommandLine"), new_pid)
        if eid == 4688:
            _process(ev, "process.parent", f.get("ParentProcessName"), None, f.get("ProcessId"))
            _set(ev, "process.integrity_level", f.get("MandatoryLabel"))
            _set(ev, "process.token.elevation_type", f.get("TokenElevationType"))
        _set(ev, "user.id", f.get("SubjectUserSid"))
        _set(ev, "user.name", f.get("SubjectUserName"))
        _set(ev, "user.domain", f.get("SubjectDomainName"))
        _set(ev, "winlog.logon.id", f.get("SubjectLogonId"))
        return
    if eid in LOGON_TARGET:
        _set(ev, "user.id", f.get("TargetUserSid", "TargetSid"))
        _set(ev, "user.name", f.get("TargetUserName"))
        _set(ev, "user.domain", f.get("TargetDomainName"))
        _set(ev, "winlog.logon.id", f.get("TargetLogonId"))
        if eid == 4672:
            _set(ev, "user.id", f.get("SubjectUserSid"))
            _set(ev, "user.name", f.get("SubjectUserName"))
            _set(ev, "user.domain", f.get("SubjectDomainName"))
            _set(ev, "winlog.logon.id", f.get("SubjectLogonId"))
    else:
        _set(ev, "user.id", f.get("SubjectUserSid"))
        _set(ev, "user.name", f.get("SubjectUserName"))
        _set(ev, "user.domain", f.get("SubjectDomainName"))
        _set(ev, "winlog.logon.id", f.get("SubjectLogonId"))
        if eid in GROUP_EVENTS:
            _set(ev, "group.name", f.get("TargetUserName"))
            _set(ev, "group.domain", f.get("TargetDomainName"))
            _set(ev, "group.id", f.get("TargetSid"))
            member = f.get("MemberName")
            if member:
                _set(ev, "user.target.name", member)
            _set(ev, "user.target.id", f.get("MemberSid"))
        else:
            _set(ev, "user.target.name", f.get("TargetUserName"))
            _set(ev, "user.target.domain", f.get("TargetDomainName"))
            _set(ev, "user.target.id", f.get("TargetUserSid", "TargetSid"))
    logon_type = f.get("LogonType")
    if logon_type:
        ev["winlog.logon.type"] = LOGON_TYPES.get(logon_type, logon_type)
    address = f.get("IpAddress", "ClientAddress")
    if address:
        _set(ev, "source.ip", address.removeprefix("::ffff:"))
    port = _int(f.get("IpPort"))
    if port:
        ev["source.port"] = port
    _set(ev, "source.domain", f.get("WorkstationName", "Workstation"))
    path = f.get("ProcessName", "CallerProcessName")
    if path:
        _process(ev, "process", path, None, f.get("ProcessId", "CallerProcessId"))
    _set(ev, "service.name", f.get("ServiceName"))
    if eid == 4697:
        _set(ev, "file.path", f.get("ServiceFileName"))
    _set(ev, "scheduled_task.name", f.get("TaskName"))


def _system_channel(ev: dict[str, Any], eid: int, f: Lookup, provider: str | None) -> None:
    if eid == 7045:
        ev["event.action"] = "service-installed"
        ev["event.category"], ev["event.type"] = ["configuration"], ["creation"]
        _set(ev, "service.name", f.get("ServiceName"))
        _set(ev, "file.path", f.get("ImagePath"))
        _set(ev, "user.name", f.get("AccountName"))
    elif eid in (7036, 7040, 7031, 7034):
        _set(ev, "service.name", f.get("param1"))
    elif eid == 104:
        ev["event.action"] = "Log clear"


def _powershell(ev: dict[str, Any], eid: int, f: Lookup) -> None:
    if eid == 4104:
        text = f.lower.get("scriptblocktext")
        if isinstance(text, str) and text != "":
            ev["powershell.file.script_block_text"] = text
            ev["powershell.file.script_block_length"] = len(text)
        _set(ev, "powershell.file.script_block_id", f.get("ScriptBlockId"))
        number = _int(f.get("MessageNumber"))
        total = _int(f.get("MessageTotal"))
        if number is not None:
            ev["powershell.sequence"] = number
        if total is not None:
            ev["powershell.total"] = total
        _file(ev, f.get("Path"))
        ev["event.action"] = "Execute a Remote Command"
        ev["event.category"], ev["event.type"] = ["process"], ["start"]
    elif eid == 4103:
        _set(ev, "powershell.command.value", f.get("Payload"))
        _set(ev, "powershell.command.invocation_details", f.get("ContextInfo"))
        ev["event.action"] = "Executing Pipeline"


def normalize(row: dict[str, Any] | Any, host_id: str | None = None) -> dict[str, Any]:
    """Build the normalized event for one stored event row (sqlite3.Row or dict)."""
    stored = row["normalized_json"]
    if isinstance(stored, str):
        try:
            stored = json.loads(stored)
        except ValueError:
            stored = {}
    stored = stored or {}
    raw = stored.get("fields") or {}
    keys = row.keys() if hasattr(row, "keys") else ()
    raw_fallback = row["raw_fallback"] if "raw_fallback" in keys else None
    system = _system_values(stored, raw_fallback)
    channel = row["channel"]
    eid = row["event_id"] if row["event_id"] is not None else stored.get("event_id")
    provider = row["provider"] if "provider" in keys else stored.get("provider")
    hostname = row["hostname"]
    f = Lookup(raw)
    ev: dict[str, Any] = {
        "_key": row["id"], "_raw": raw, "_lower": f.lower, "_m": {},
        "@timestamp": row["event_time"], "host.name": hostname, "host.hostname": hostname,
        "host.id": host_id or (stored.get("computer") or hostname), "host.os.type": "windows",
        "host.os.family": "windows", "winlog.channel": channel, "event.kind": "event",
        "griffendo.parser_status": "error" if stored.get("parse_error") else "ok",
    }
    _set(ev, "winlog.computer_name", stored.get("computer"))
    if eid is not None:
        ev["event.code"] = str(eid)
        ev["winlog.event_id"] = eid
    _set(ev, "event.provider", provider)
    _set(ev, "winlog.provider_name", provider)
    record = row["record_id"] if "record_id" in keys else stored.get("record_id")
    if record is not None:
        ev["winlog.record_id"] = record
    _set(ev, "event.ingested", row["collected_at"] if "collected_at" in keys else None)
    level = stored.get("level")
    _set(ev, "log.level", level)
    level_code = _LEVEL_NAMES.get(level or "", "0" if level == "Informational" else "")
    keywords = system.get("keywords")
    if keywords:
        ev["winlog.keywords"] = keywords
    for name, target in (("task", "winlog.task"), ("opcode", "winlog.opcode")):
        _set(ev, target, system.get(name))
    pid = _int(system.get("process_id"))
    if pid is not None:
        ev["winlog.process.pid"] = pid
    tid = _int(system.get("thread_id"))
    if tid is not None:
        ev["winlog.process.thread.id"] = tid
    _set(ev, "winlog.user.identifier", system.get("user_id"))
    # Outcome and Wazuh's severityValue: audit keywords first, otherwise the level.
    mask = _int(keywords) if keywords else None
    raw_level = system.get("level") or level_code
    if mask and mask & _AUDIT_FAILURE:
        ev["event.outcome"] = "failure"
        ev["griffendo.severity_value"] = "AUDIT_FAILURE"
    elif mask and mask & _AUDIT_SUCCESS:
        ev["event.outcome"] = "success"
        ev["griffendo.severity_value"] = "AUDIT_SUCCESS"
    else:
        ev["griffendo.severity_value"] = _SEVERITY_VALUE.get(str(raw_level), "INFORMATION")
    dataset = schema.DATASETS.get(next((name for name in schema.DATASETS if name.lower() == (channel or "").lower()),
                                       ""))
    if dataset:
        ev["data_stream.dataset"] = dataset
    channel_l = (channel or "").lower()
    if eid is not None:
        if channel_l == schema.SYSMON.lower():
            _sysmon(ev, eid, f)
        elif channel_l == "security":
            _security(ev, eid, f)
        elif channel_l == "system":
            _system_channel(ev, eid, f, provider)
        elif channel_l in (schema.POWERSHELL.lower(),):
            _powershell(ev, eid, f)
        elif channel_l == schema.TASKS.lower():
            _set(ev, "scheduled_task.name", f.get("TaskName"))
            _set(ev, "user.name", f.get("UserName", "UserContext"))
    return ev


# ---------------------------------------------------------------------------------------- field access
def get(ev: dict[str, Any], field: str) -> Any:
    """Value of a normalized field, or None when the event does not carry it."""
    value = ev.get(field)
    if value is not None:
        return value
    if field.startswith("winlog.event_data."):
        raw = ev["_lower"].get(field[18:].lower())
        if raw is None:
            return None
        return raw
    if field.endswith(".caseless"):
        return ev.get(field[:-9])
    return None


def entity(ev: dict[str, Any]) -> dict[str, str]:
    """Identifiers used to relate events (only real, non-system values)."""
    result: dict[str, str] = {}
    logon = ev.get("winlog.logon.id")
    if isinstance(logon, str) and logon.lower() not in schema.SYSTEM_LOGON_IDS:
        result["logon"] = logon.lower()
    sid = ev.get("user.id")
    name = ev.get("user.name")
    # The account name is used (not the SID) because Sysmon events carry only DOMAIN\name.
    system_sid = isinstance(sid, str) and (sid.lower() in schema.SYSTEM_SIDS or sid.lower().startswith(("s-1-5-90-",
                                                                                                         "s-1-5-96-")))
    if isinstance(name, str) and name.lower() not in schema.SYSTEM_USERS and not name.endswith("$") \
            and not name.lower().startswith(("dwm-", "umfd-")) and not system_sid:
        result["user"] = name.lower()
    elif isinstance(sid, str) and not system_sid and not name:
        result["user"] = sid.lower()
    guid = ev.get("process.entity_id")
    if isinstance(guid, str):
        result["process"] = guid
    return result


def summary(ev: dict[str, Any]) -> dict[str, Any]:
    """Compact evidence snapshot kept with a detection (outlives event retention)."""
    keep = ("@timestamp", "event.code", "winlog.channel", "event.provider", "winlog.record_id", "host.name",
            "user.name", "user.domain", "user.id", "winlog.logon.id", "winlog.logon.type", "source.ip",
            "process.name", "process.executable", "process.pid", "process.entity_id", "process.command_line",
            "process.parent.name", "process.parent.executable", "process.parent.pid", "process.parent.command_line",
            "destination.ip", "destination.port", "dns.question.name", "file.path", "registry.path",
            "registry.data.strings", "service.name", "scheduled_task.name", "dll.path", "group.name",
            "user.target.name", "event.action", "event.outcome")
    result = {key: ev[key] for key in keep if key in ev}
    text = ev.get("powershell.file.script_block_text")
    if text:
        result["powershell.file.script_block_text"] = text[:2000] + ("…" if len(text) > 2000 else "")
    result["event_key"] = ev["_key"]
    return result
