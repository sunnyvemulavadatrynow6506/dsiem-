"""Synthetic Windows events for tests and demos.

Everything produced here is fabricated test data.  Hosts are named
SYNTHETIC-* and the agent id starts with 'synthetic-' so nothing can be
mistaken for real host telemetry.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SYNTHETIC_AGENT = "synthetic-agent-0001"
SYNTHETIC_HOST = "SYNTHETIC-WS01"

PROVIDERS = {
    "Security": "Microsoft-Windows-Security-Auditing",
    "System": "Service Control Manager",
    "Microsoft-Windows-Windows Defender/Operational": "Microsoft-Windows-Windows Defender",
    "Microsoft-Windows-WMI-Activity/Operational": "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-TaskScheduler/Operational": "Microsoft-Windows-TaskScheduler",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    "Application": "Application Error",
}


def system_time(when: datetime | None) -> str | None:
    if when is None:
        return None
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"   # 7 fractional digits like Windows


def event_xml(event_id: int, channel: str, when: datetime | None, record_id: int, data: dict[str, str] | None = None,
              provider: str | None = None, level: int = 0, user_data: bool = False, computer: str = SYNTHETIC_HOST) -> str:
    provider = provider or PROVIDERS.get(channel, "Synthetic-Provider")
    time_element = f'<TimeCreated SystemTime="{system_time(when)}"/>' if when is not None else ""
    if user_data:
        body = "<UserData><LogFileCleared>" + "".join(
            f"<{key}>{escape(value)}</{key}>" for key, value in (data or {}).items()) + "</LogFileCleared></UserData>"
    else:
        body = "<EventData>" + "".join(
            f'<Data Name="{escape(key)}">{escape(value)}</Data>' for key, value in (data or {}).items()) + "</EventData>"
    return (f'<Event xmlns="{NS}"><System><Provider Name="{escape(provider)}"/><EventID>{event_id}</EventID>'
            f"<Version>0</Version><Level>{level}</Level>{time_element}<EventRecordID>{record_id}</EventRecordID>"
            f"<Channel>{escape(channel)}</Channel><Computer>{escape(computer)}</Computer></System>{body}</Event>")


def envelope(event_id: int, channel: str, when: datetime | None, record_id: int, host: str = SYNTHETIC_HOST, **kwargs) -> dict:
    xml = event_xml(event_id, channel, when, record_id, computer=host, **kwargs)
    # Same identity scheme as the real collector: sha256(host|channel|record_id|xml).
    key = hashlib.sha256(f"{host}|{channel}|{record_id}|{xml}".encode("utf-8")).hexdigest()
    return {"id": key, "channel": channel, "record_id": record_id, "xml": xml}


def batch(events: list[dict], host: str = SYNTHETIC_HOST, agent: str = SYNTHETIC_AGENT) -> dict:
    return {"agent_id": agent, "hostname": host, "os_name": "Windows", "events": events}


def demo_dataset(now: datetime | None = None) -> list[dict]:
    """A varied week of synthetic activity across severities, for UI review."""
    now = now or datetime.now(timezone.utc)
    h = lambda hours: now - timedelta(hours=hours)
    sec, sysc = "Security", "System"
    de = "Microsoft-Windows-Windows Defender/Operational"
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    items = [
        (1102, sec, h(2), {"SubjectUserName": "synthetic.admin", "SubjectDomainName": "SYNTHLAB"}, dict(provider="Microsoft-Windows-Eventlog", user_data=True)),
        (4719, sec, h(30), {"SubjectUserName": "synthetic.admin", "AuditPolicyChanges": "%%8448"}, {}),
        (7045, sysc, h(5), {"ServiceName": "SynthUpdater", "ImagePath": "C:\\ProgramData\\synth\\svc.exe", "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}, {}),
        (1116, de, h(7), {"Threat Name": "Synthetic:Test/EICAR_Sample", "Severity Name": "Severe", "Path": "file:_C:\\Users\\demo\\Downloads\\eicar.com", "Process Name": "C:\\Windows\\explorer.exe", "Detection User": "SYNTHLAB\\demo"}, {}),
        (1117, de, h(7), {"Threat Name": "Synthetic:Test/EICAR_Sample", "Action Name": "Quarantine", "Path": "file:_C:\\Users\\demo\\Downloads\\eicar.com"}, {}),
        (4720, sec, h(26), {"TargetUserName": "svc_synth", "TargetDomainName": "SYNTHETIC-WS01", "SubjectUserName": "synthetic.admin"}, {}),
        (4732, sec, h(25), {"MemberName": "-", "MemberSid": "S-1-5-21-0-0-0-1009", "TargetUserName": "Administrators", "SubjectUserName": "synthetic.admin"}, {}),
        (4698, sec, h(24), {"TaskName": "\\SynthNightly", "TaskContent": "<Task>...</Task>", "SubjectUserName": "synthetic.admin"}, {}),
        (4740, sec, h(12), {"TargetUserName": "demo", "TargetDomainName": "SYNTHETIC-WS02"}, {}),
        (6008, sysc, h(60), {"param1": "10:14:02", "param2": "10/23/2026"}, dict(provider="EventLog", level=1)),
        (41, sysc, h(60), {"BugcheckCode": "0", "PowerButtonTimestamp": "0"}, dict(provider="Microsoft-Windows-Kernel-Power", level=1)),
        (7040, sysc, h(80), {"param1": "Background Intelligent Transfer Service", "param2": "auto start", "param3": "demand start", "param4": "BITS"}, {}),
        (4616, sec, h(90), {"PreviousTime": "2026-10-22T01:00:00Z", "NewTime": "2026-10-22T01:00:03Z", "ProcessName": "C:\\Windows\\System32\\svchost.exe"}, {}),
        (6416, sec, h(40), {"DeviceDescription": "Synthetic USB Mass Storage", "ClassName": "DiskDrive"}, {}),
        (8, sysmon, h(3), {"SourceImage": "C:\\Synth\\loader.exe", "TargetImage": "C:\\Windows\\System32\\notepad.exe"}, {}),
        (4608, sec, h(59), {}, {}),
        (6005, sysc, h(59), {}, dict(provider="EventLog")),
        (5007, de, h(10), {"Old Value": "", "New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Synth = 0x0"}, {}),
    ]
    events = []
    record = 1000
    for event_id, channel, when, data, extra in items:
        record += 1
        events.append(envelope(event_id, channel, when, record, data=data, **extra))
    # Repeated failed logons: every one must be flagged individually.
    for minute in range(6):
        record += 1
        events.append(envelope(4625, sec, now - timedelta(hours=4, minutes=minute), record,
                               data={"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "198.51.100.23",
                                     "WorkstationName": "SYNTH-ATTACKER", "Status": "0xc000006d", "SubStatus": "0xc000006a"}))
    # Non-catalog noise and an old event (outside the window) for contrast.
    for offset in range(5):
        record += 1
        events.append(envelope(4624, sec, now - timedelta(hours=offset), record, data={"TargetUserName": "demo", "LogonType": "2"}))
    record += 1
    events.append(envelope(7036, sysc, now - timedelta(hours=1), record, data={"param1": "Windows Update", "param2": "running"}))
    record += 1
    events.append(envelope(4720, sec, now - timedelta(days=9), record, data={"TargetUserName": "old_account"}))
    return events
