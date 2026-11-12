"""Backend-only Windows Event XML parsing and normalization."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

LEVELS = {
    "0": "Informational",  # LogAlways: used by most Security audit events
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Informational",
    "5": "Verbose",
}

# Values Windows writes when a field is not applicable.  They are "truthy"
# strings, so they used to win over the real value further down the list.
_PLACEHOLDERS = {"", "-", "--", "n/a", "(null)", "null", "none", "0x0", "0x00000000", "unknown"}

_PATH_FIELDS = (
    "NewProcessName", "Image", "ProcessName", "Application", "SourceImage",
    "ImagePath", "ServiceFileName", "CallerProcessName", "ClientProcessName",
)
_PARENT_PATH_FIELDS = ("ParentProcessName", "ParentImage", "CreatorProcessName")
_PID_FIELDS = ("NewProcessId", "ProcessId", "ProcessID", "SourceProcessId", "CallerProcessId")
_PARENT_PID_FIELDS = ("ParentProcessId", "ParentProcessID", "CreatorProcessId")
_COMMAND_FIELDS = ("CommandLine", "ProcessCommandLine", "ParentCommandLine")
_USER_FIELDS = ("TargetUserName", "SubjectUserName", "User", "UserName", "AccountName", "Account")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _meaningful(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _PLACEHOLDERS


def _integer(value: str | None) -> int | None:
    """Parse decimal or 0x-prefixed hexadecimal ids (never guess hex for plain digits)."""
    if not _meaningful(value):
        return None
    text = value.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _base_name(path: str | None) -> str | None:
    """File name of a Windows (or POSIX) path; tolerates quotes and trailing slashes."""
    if not _meaningful(path):
        return None
    text = path.strip().strip('"').rstrip("\\/ ")
    name = text.replace("/", "\\").rsplit("\\", 1)[-1].strip()
    return name or None


def _executable_from_command(command: str | None) -> str | None:
    """Best-effort executable path from a command line (quoted or unquoted)."""
    if not _meaningful(command):
        return None
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 1 else text[1:]
    lowered = text.lower()
    for ext in (".exe", ".com", ".bat", ".cmd", ".scr"):
        index = lowered.find(ext)
        if index != -1:
            return text[: index + len(ext)]
    return text.split(" ", 1)[0]


def _clean_path(path: str | None) -> str | None:
    """Drop quotes and trailing arguments (service ImagePath is often '"C:\\x.exe" -k grp')."""
    if not _meaningful(path):
        return None
    text = path.strip()
    if text.startswith('"') or " -" in text or " /" in text:
        return _executable_from_command(text) or text
    return text


def _strip_domain(value: str | None) -> str | None:
    if not _meaningful(value):
        return None
    text = value.strip()
    return text.rsplit("\\", 1)[-1] if "\\" in text else text


def parse_event(raw_xml: str) -> dict[str, Any]:
    """Normalize common event fields while leaving the original XML untouched."""
    result: dict[str, Any] = {
        "timestamp": None, "provider": None, "event_id": None, "level": None,
        "record_id": None, "channel": None, "computer": None,
        "user": None, "process_name": None, "process_path": None, "pid": None,
        "parent_process_name": None, "parent_pid": None, "command_line": None,
        "fields": {},
        "system": {},
    }
    try:
        # ElementTree never resolves external entities; expat (>= 2.4) limits entity expansion.
        root = ET.fromstring(raw_xml)
    except ET.ParseError as error:
        result["parse_error"] = f"Invalid Windows Event XML ({error})"
        return result

    system = None
    event_fields: dict[str, str] = {}
    unnamed = 0

    def add_field(key: str, text: str) -> None:
        # Never silently overwrite a repeated field name.
        final = key
        suffix = 2
        while final in event_fields:
            final = f"{key}_{suffix}"
            suffix += 1
        event_fields[final] = text

    for element in root.iter():
        name = _local_name(element.tag)
        if name == "System":
            system = element
        elif name == "Data":
            key = element.attrib.get("Name")
            if not key:
                key = f"field_{unnamed}"
                unnamed += 1
            add_field(key, (element.text or "").strip())
        elif name == "UserData":
            # UserData wraps a provider-specific element; its schema differs per provider and
            # can nest several levels, so every text-bearing leaf is kept under its own name.
            for wrapper in element:
                if len(wrapper) == 0:
                    if (wrapper.text or "").strip():
                        add_field(_local_name(wrapper.tag), wrapper.text.strip())
                    continue
                for leaf in wrapper.iter():
                    if leaf is not wrapper and len(leaf) == 0 and (leaf.text or "").strip():
                        add_field(_local_name(leaf.tag), leaf.text.strip())

    if system is None:
        result["parse_error"] = "Event XML has no <System> element"
    else:
        for element in system:
            name = _local_name(element.tag)
            if name == "Provider":
                result["provider"] = element.attrib.get("Name")
            elif name == "EventID":
                result["event_id"] = _integer((element.text or "").strip())
            elif name == "Level":
                raw_level = (element.text or "").strip()
                result["level"] = LEVELS.get(raw_level, raw_level or None)
            elif name == "TimeCreated":
                result["timestamp"] = element.attrib.get("SystemTime")
            elif name == "EventRecordID":
                result["record_id"] = _integer((element.text or "").strip())
            elif name == "Channel":
                result["channel"] = (element.text or "").strip() or None
            elif name == "Computer":
                result["computer"] = (element.text or "").strip() or None
            # v5: values the detection engine needs (audit outcome keywords, Wazuh severityValue, execution ids).
            if name in ("Keywords", "Task", "Opcode", "Level") and (element.text or "").strip():
                result["system"][name.lower()] = element.text.strip()
            elif name == "Execution":
                for attribute, key in (("ProcessID", "process_id"), ("ThreadID", "thread_id")):
                    if element.attrib.get(attribute):
                        result["system"][key] = element.attrib[attribute]
            elif name == "Security" and element.attrib.get("UserID"):
                result["system"]["user_id"] = element.attrib["UserID"]

    lowered = {key.lower(): value for key, value in event_fields.items()}

    def first(names: tuple[str, ...]) -> str | None:
        for candidate in names:
            value = lowered.get(candidate.lower())
            if _meaningful(value):
                return value.strip()
        return None

    command_line = first(_COMMAND_FIELDS[:2])
    process_path = _clean_path(first(_PATH_FIELDS)) or _executable_from_command(command_line)
    parent_path = _clean_path(first(_PARENT_PATH_FIELDS)) or _executable_from_command(first(("ParentCommandLine",)))

    pid = None
    for candidate in _PID_FIELDS:
        pid = _integer(lowered.get(candidate.lower()))
        if pid is not None:
            break
    parent_pid = None
    for candidate in _PARENT_PID_FIELDS:
        parent_pid = _integer(lowered.get(candidate.lower()))
        if parent_pid is not None:
            break

    # Event 4688 (process creation): "ProcessId" is the CREATOR (parent) process,
    # while "NewProcessId" is the new process.  There is no CreatorProcessId field
    # on most Windows versions, so parent_pid used to be empty for every 4688.
    if parent_pid is None and _integer(lowered.get("newprocessid")) is not None:
        parent_pid = _integer(lowered.get("processid"))

    result.update(
        user=_strip_domain(first(_USER_FIELDS)),
        process_name=_base_name(process_path),
        process_path=process_path,
        pid=pid,
        parent_process_name=_base_name(parent_path),
        parent_pid=parent_pid,
        command_line=command_line,
        fields=event_fields,
    )
    return result
