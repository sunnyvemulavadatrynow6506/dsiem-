"""Normalized event schema and per-source field availability.

Every collected Windows event is normalized into a flat dictionary keyed by
ECS-style dotted names (``process.name``, ``source.ip`` ...).  ECS names were
chosen because both supplied rule sets were written against them (Elastic) or
map onto them one-to-one (Wazuh ``win.eventdata.*`` -> ``winlog.event_data.*``),
so a translated rule reads the same as its original.

A field is only present when the event really carries the value (``_meaningful``
in the normalizer).  ``None`` is never stored: "missing" means the key is absent,
an empty string means Windows wrote an empty value.

SOURCES describes which fields each kind of event can provide.  The rule
importer uses it to decide, per rule and per source, whether every condition
can be evaluated (see tools/rules_import/availability.py), and the custom-rule
builder uses it to refuse conditions on fields Griffendo never collects.
"""
from __future__ import annotations

from typing import Any

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
APPLICATION = "Application"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_CLASSIC = "Windows PowerShell"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
FIREWALL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
TASKS = "Microsoft-Windows-TaskScheduler/Operational"
WMI = "Microsoft-Windows-WMI-Activity/Operational"

# Fields every normalized event has (when the value exists in the event).
COMMON_FIELDS = {
    "@timestamp", "event.code", "event.provider", "event.kind", "event.category", "event.type", "event.action",
    "event.outcome", "event.ingested", "event.severity", "log.level", "host.name", "host.hostname", "host.id",
    "host.os.type", "host.os.family", "winlog.channel", "winlog.provider_name", "winlog.record_id",
    "winlog.computer_name", "winlog.event_id", "winlog.keywords", "winlog.task", "winlog.opcode",
    "winlog.process.pid", "winlog.process.thread.id", "winlog.user.identifier", "data_stream.dataset",
    "griffendo.parser_status", "griffendo.severity_value",
}
# ``winlog.event_data.<Name>`` is always resolvable for Windows sources (it is the event's own EventData).
RAW_PREFIX = "winlog.event_data."

PROC = ("pid", "entity_id", "executable", "name", "command_line", "args", "args_count")
_SYSMON_PROCESS = {f"process.{name}" for name in PROC} | {
    "process.working_directory", "process.pe.original_file_name", "process.pe.description", "process.pe.product",
    "process.pe.company", "process.pe.file_version", "process.hash.md5", "process.hash.sha1", "process.hash.sha256",
    "process.pe.imphash", "process.parent.pid", "process.parent.entity_id", "process.parent.executable",
    "process.parent.name", "process.parent.command_line", "process.parent.args", "process.parent.args_count",
    "user.name", "user.domain", "winlog.logon.id", "process.integrity_level",
}
_SECURITY_PROCESS = {
    "process.pid", "process.executable", "process.name", "process.command_line", "process.args", "process.args_count",
    "process.parent.pid", "process.parent.executable", "process.parent.name",
    "user.id", "user.name", "user.domain", "winlog.logon.id", "process.integrity_level", "process.token.elevation_type",
}
_SYSMON_ACTOR = {"process.pid", "process.entity_id", "process.executable", "process.name", "user.name", "user.domain"}
_SECURITY_USER = {"user.id", "user.name", "user.domain", "user.target.id", "user.target.name", "user.target.domain",
                  "winlog.logon.id", "winlog.logon.type", "source.ip", "source.port", "source.domain",
                  "process.pid", "process.executable", "process.name", "group.id", "group.name", "group.domain",
                  "service.name", "file.path", "scheduled_task.name"}

# Source catalogue: (channel, event ids) -> what the normalizer produces.
#   category  : EQL event category keyword this source answers to ("process where ...")
#   ecs       : event.category / event.type / event.action values the normalizer writes
#   dataset   : data_stream.dataset (Elastic integration name, used by a few rules)
#   fields    : ECS fields that can be present
SOURCES: dict[str, dict[str, Any]] = {
    "sysmon:1": {"channel": SYSMON, "event_ids": [1], "category": "process",
                 "ecs": {"event.category": ["process"], "event.type": ["start", "process_start"],
                         "event.action": ["Process Create (rule: ProcessCreate)"]},
                 "fields": _SYSMON_PROCESS},
    "sysmon:5": {"channel": SYSMON, "event_ids": [5], "category": "process",
                 "ecs": {"event.category": ["process"], "event.type": ["end"],
                         "event.action": ["Process terminated (rule: ProcessTerminate)"]},
                 "fields": _SYSMON_ACTOR | {"winlog.logon.id"}},
    "security:4688": {"channel": SECURITY, "event_ids": [4688], "category": "process",
                      "ecs": {"event.category": ["process"], "event.type": ["start", "process_start"],
                              "event.action": ["created-process"]},
                      "fields": _SECURITY_PROCESS},
    "security:4689": {"channel": SECURITY, "event_ids": [4689], "category": "process",
                      "ecs": {"event.category": ["process"], "event.type": ["end"], "event.action": ["exited-process"]},
                      "fields": {"process.pid", "process.executable", "process.name", "user.id", "user.name",
                                 "user.domain", "winlog.logon.id"}},
    "sysmon:3": {"channel": SYSMON, "event_ids": [3], "category": "network",
                 "ecs": {"event.category": ["network"], "event.type": ["start", "connection", "protocol"],
                         "event.action": ["Network connection detected (rule: NetworkConnect)"]},
                 "fields": _SYSMON_ACTOR | {"network.transport", "network.direction", "network.type", "network.protocol",
                                            "source.ip", "source.port", "source.domain", "destination.ip",
                                            "destination.port", "destination.domain"}},
    "sysmon:22": {"channel": SYSMON, "event_ids": [22], "category": "network",
                  "ecs": {"event.category": ["network"], "event.type": ["protocol", "info"],
                          "event.action": ["Dns query (rule: DnsQuery)", "DNSEvent (DNS query)"]},
                  "fields": _SYSMON_ACTOR | {"dns.question.name", "dns.answers.data", "dns.resolved_ip",
                                             "network.protocol"}},
    # Image loads: Elastic's Sysmon mapping uses both dll.* and file.* names (rules use either), category
    # "process" (older integration) and "library" (newer); both are written.
    "sysmon:7": {"channel": SYSMON, "event_ids": [7], "category": "library",
                 "ecs": {"event.category": ["process", "library"], "event.type": ["change"],
                         "event.action": ["Image loaded (rule: ImageLoad)", "load"]},
                 "fields": _SYSMON_ACTOR | {"dll.name", "dll.path", "dll.pe.original_file_name", "dll.pe.description",
                                            "dll.pe.product", "dll.pe.company", "dll.pe.file_version",
                                            "dll.hash.md5", "dll.hash.sha1", "dll.hash.sha256", "dll.pe.imphash",
                                            "dll.code_signature.exists", "dll.code_signature.subject_name",
                                            "dll.code_signature.status", "dll.code_signature.trusted",
                                            "file.path", "file.name", "file.pe.original_file_name", "file.pe.description",
                                            "file.pe.product", "file.pe.company", "file.pe.imphash", "file.hash.md5",
                                            "file.hash.sha1", "file.hash.sha256", "file.code_signature.exists",
                                            "file.code_signature.subject_name", "file.code_signature.status",
                                            "file.code_signature.trusted"}},
    "sysmon:6": {"channel": SYSMON, "event_ids": [6], "category": "driver",  # file.code_signature from Signature*
                 "ecs": {"event.category": ["driver"], "event.type": ["start", "info"],
                         "event.action": ["Driver loaded (rule: DriverLoad)"]},
                 "fields": {"file.path", "file.name", "file.hash.md5", "file.hash.sha1", "file.hash.sha256",
                            "file.code_signature.exists", "file.code_signature.subject_name",
                            "file.code_signature.status", "file.code_signature.trusted"}},
    "sysmon:8": {"channel": SYSMON, "event_ids": [8], "category": "process",
                 "ecs": {"event.category": ["process"], "event.type": ["change"],
                         "event.action": ["CreateRemoteThread detected (rule: CreateRemoteThread)"]},
                 "fields": {"process.pid", "process.entity_id", "process.executable", "process.name",
                            "process.target.executable", "process.target.name", "process.target.pid"}},
    "sysmon:10": {"channel": SYSMON, "event_ids": [10], "category": "process",
                  "ecs": {"event.category": ["process"], "event.type": ["access"],
                          "event.action": ["Process accessed (rule: ProcessAccess)"]},
                  "fields": {"process.pid", "process.entity_id", "process.executable", "process.name", "user.name",
                             "user.domain", "process.target.executable", "process.target.name", "process.target.pid"}},
    "sysmon:11": {"channel": SYSMON, "event_ids": [11], "category": "file",
                  "ecs": {"event.category": ["file"], "event.type": ["creation"],
                          "event.action": ["File created (rule: FileCreate)"]},
                  "fields": _SYSMON_ACTOR | {"file.path", "file.name", "file.extension", "file.directory"}},
    "sysmon:2": {"channel": SYSMON, "event_ids": [2], "category": "file",
                 "ecs": {"event.category": ["file"], "event.type": ["change"],
                         "event.action": ["File creation time changed (rule: FileCreateTime)"]},
                 "fields": _SYSMON_ACTOR | {"file.path", "file.name", "file.extension", "file.directory"}},
    "sysmon:15": {"channel": SYSMON, "event_ids": [15], "category": "file",
                  "ecs": {"event.category": ["file"], "event.type": ["creation"],
                          "event.action": ["File stream created (rule: FileCreateStreamHash)"]},
                  "fields": _SYSMON_ACTOR | {"file.path", "file.name", "file.extension", "file.directory",
                                             "file.hash.md5", "file.hash.sha1", "file.hash.sha256"}},
    "sysmon:23": {"channel": SYSMON, "event_ids": [23, 26], "category": "file",
                  "ecs": {"event.category": ["file"], "event.type": ["deletion"],
                          "event.action": ["File Delete archived (rule: FileDelete)", "File Delete logged (rule: FileDeleteDetected)",
                                           "deletion"]},
                  "fields": _SYSMON_ACTOR | {"file.path", "file.name", "file.extension", "file.directory",
                                             "file.hash.md5", "file.hash.sha1", "file.hash.sha256"}},
    "sysmon:29": {"channel": SYSMON, "event_ids": [29], "category": "file",
                  "ecs": {"event.category": ["file"], "event.type": ["creation"],
                          "event.action": ["File Executable Detected (rule: FileExecutableDetected)"]},
                  "fields": _SYSMON_ACTOR | {"file.path", "file.name", "file.extension", "file.directory",
                                             "file.hash.md5", "file.hash.sha1", "file.hash.sha256"}},
    "sysmon:12": {"channel": SYSMON, "event_ids": [12, 13, 14], "category": "registry",
                  # event.type follows the Sysmon EventType: SetValue/RenameKey -> change, CreateKey -> creation,
                  # DeleteKey/DeleteValue -> deletion.
                  "ecs": {"event.category": ["registry"], "event.type": ["change", "creation", "deletion"],
                          "event.action": ["Registry value set (rule: RegistryEvent)",
                                           "Registry object added or deleted (rule: RegistryEvent)",
                                           "Registry object renamed (rule: RegistryEvent)"]},
                  "fields": _SYSMON_ACTOR | {"registry.path", "registry.hive", "registry.key", "registry.value",
                                             "registry.data.strings", "registry.data.type"}},
    "sysmon:17": {"channel": SYSMON, "event_ids": [17, 18], "category": "file",
                  "ecs": {"event.category": ["file"], "event.type": ["creation", "access"],
                          "event.action": ["Pipe Created (rule: PipeEvent)", "Pipe Connected (rule: PipeEvent)"]},
                  "fields": _SYSMON_ACTOR | {"file.name"}},
    "sysmon:19": {"channel": SYSMON, "event_ids": [19, 20, 21], "category": "any",
                  "ecs": {"event.category": ["configuration"], "event.type": ["change"], "event.action": []},
                  "fields": {"user.name", "user.domain"}},
    "sysmon:25": {"channel": SYSMON, "event_ids": [25], "category": "process",
                  "ecs": {"event.category": ["process"], "event.type": ["change"],
                          "event.action": ["Process Tampering (rule: ProcessTampering)"]},
                  "fields": _SYSMON_ACTOR},
    "powershell:4104": {"channel": POWERSHELL, "event_ids": [4104], "category": "process",
                        "ecs": {"event.category": ["process"], "event.type": ["start", "info"],
                                "event.action": ["Execute a Remote Command"]},
                        "fields": {"powershell.file.script_block_text", "powershell.file.script_block_id",
                                   "powershell.file.script_block_length", "powershell.sequence", "powershell.total",
                                   "file.path", "file.name", "file.directory", "user.id"}},
    "powershell:4103": {"channel": POWERSHELL, "event_ids": [4103], "category": "process",
                        "ecs": {"event.category": ["process"], "event.type": ["info"],
                                "event.action": ["Executing Pipeline"]},
                        "fields": {"powershell.command.value", "powershell.command.invocation_details", "user.id"}},
}

# Generic sources: any other (channel, event id).  Security events get the user / logon / source mapping.
GENERIC_FIELDS = {
    SECURITY: _SECURITY_USER,
    SYSTEM: {"service.name", "file.path", "user.id"},
    TASKS: {"scheduled_task.name", "user.id"},
}

# Elastic integration dataset names (data_stream.dataset), for the few rules that test it.
DATASETS = {
    SYSMON: "windows.sysmon_operational", SECURITY: "system.security", SYSTEM: "system.system",
    APPLICATION: "system.application", POWERSHELL: "windows.powershell_operational",
    POWERSHELL_CLASSIC: "windows.powershell", DEFENDER: "windows.windows_defender",
}

# Fields that are only produced by an EDR agent (Elastic Defend and similar) and that no Windows
# event log carries.  The importer marks a rule unsupported when a required condition needs one.
EDR_ONLY_PREFIXES = (
    "process.Ext.", "process.parent.Ext.", "process.code_signature.", "process.parent.code_signature.",
    "process.thread.", "process.parent.thread.", "dll.Ext.", "file.Ext.", "process.pe.Ext.",
    "process.parent.pe.", "process.executable.caseless", "process.Ext", "file.code_signature.",
    "process.hash.", "file.pe.", "process.tty", "process.session_leader", "process.group_leader",
    "process.entry_leader", "Effective_process.", "process.Ext.effective_parent.", "Target.",
)
# Well-known accounts/logon sessions never used to join different rules into one detection.
SYSTEM_SIDS = {"s-1-5-18", "s-1-5-19", "s-1-5-20"}
SYSTEM_LOGON_IDS = {"0x3e7", "0x3e4", "0x3e5", "999", "996", "997"}
SYSTEM_USERS = {"system", "local service", "network service", "anonymous logon", "-", ""}

# Fields shown in the custom-rule builder (every normalized field with a label).
BUILDER_FIELDS: dict[str, str] = {
    "event.code": "Event ID", "winlog.channel": "Channel", "event.provider": "Provider",
    "log.level": "Event level (Critical/Error/Warning/Informational/Verbose)", "event.outcome": "Outcome (success/failure)",
    "user.name": "User name", "user.id": "User SID", "user.domain": "User domain", "winlog.logon.id": "Logon ID",
    "winlog.logon.type": "Logon type (Interactive, Network, RemoteInteractive...)",
    "process.name": "Process name", "process.executable": "Process path", "process.command_line": "Command line",
    "process.args": "Command-line arguments", "process.pid": "Process ID", "process.entity_id": "Process GUID (Sysmon)",
    "process.parent.name": "Parent process name", "process.parent.executable": "Parent process path",
    "process.parent.command_line": "Parent command line (Sysmon)", "process.pe.original_file_name": "Original file name (Sysmon)",
    "source.ip": "Source IP", "source.port": "Source port", "destination.ip": "Destination IP (Sysmon)",
    "destination.port": "Destination port (Sysmon)", "dns.question.name": "DNS query (Sysmon)",
    "file.path": "File path", "file.name": "File name", "file.extension": "File extension",
    "registry.path": "Registry path (Sysmon)", "registry.value": "Registry value name (Sysmon)",
    "registry.data.strings": "Registry data (Sysmon)", "service.name": "Service name",
    "scheduled_task.name": "Scheduled task name", "dll.name": "Loaded DLL name (Sysmon)", "dll.path": "Loaded DLL path (Sysmon)",
    "powershell.file.script_block_text": "PowerShell script block text", "group.name": "Group name",
    "user.target.name": "Target user name",
}


def source_key(channel: str | None, event_id: int | None) -> str:
    """Source key for a stored event (specific source when known, else 'generic:<channel>:<id>')."""
    channel_l = (channel or "").lower()
    if channel_l == SYSMON.lower():
        for key in _SYSMON_KEYS.get(event_id, ()):
            return key
    elif channel_l == "security" and event_id in (4688, 4689):
        return f"security:{event_id}"
    elif channel_l == POWERSHELL.lower() and event_id in (4103, 4104):
        return f"powershell:{event_id}"
    return f"generic:{channel or ''}:{event_id}"


_SYSMON_KEYS: dict[int, tuple[str, ...]] = {}
for _key, _source in SOURCES.items():
    if _source["channel"] == SYSMON:
        for _eid in _source["event_ids"]:
            _SYSMON_KEYS.setdefault(_eid, (_key,))


def fields_for(key: str, channel: str | None = None) -> set[str]:
    if key in SOURCES:
        return COMMON_FIELDS | SOURCES[key]["fields"]
    for name, extra in GENERIC_FIELDS.items():
        if (channel or "").lower() == name.lower():
            return COMMON_FIELDS | extra
    return set(COMMON_FIELDS)


def field_available(field: str, key: str, channel: str | None = None) -> bool:
    name = field.removesuffix(".caseless")
    if name.startswith(RAW_PREFIX):
        return True
    if any(name.startswith(prefix) for prefix in EDR_ONLY_PREFIXES):
        # A few EDR-style names are produced from Sysmon data with a documented derivation.
        return name in fields_for(key, channel)
    return name in fields_for(key, channel)
