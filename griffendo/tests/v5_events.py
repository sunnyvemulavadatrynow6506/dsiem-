"""Synthetic Windows events for the v5 engine tests (fabricated; hosts are SYNTHETIC-*)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import synthetic

SYSMON = "Microsoft-Windows-Sysmon/Operational"
NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


class Builder:
    def __init__(self, start: datetime | None = None):
        self.record = 10_000
        self.events: list[dict] = []
        self.t = start or NOW() - timedelta(hours=2)

    def at(self, seconds: float) -> datetime:
        return self.t + timedelta(seconds=seconds)

    def add(self, eid: int, channel: str, when: datetime, data: dict, **kwargs) -> dict:
        self.record += 1
        provider = kwargs.pop("provider", "Microsoft-Windows-Sysmon" if channel == SYSMON else None)
        event = synthetic.envelope(eid, channel, when, self.record, data=data, provider=provider, **kwargs)
        self.events.append(event)
        return event

    def process(self, when, guid, pid, image, command, parent_guid, parent_pid, parent_image, user="LAB\\alice",
                logon="0x5555", **extra):
        data = {"ProcessGuid": "{%s}" % guid, "ProcessId": str(pid), "Image": image, "CommandLine": command,
                "ParentProcessGuid": "{%s}" % parent_guid, "ParentProcessId": str(parent_pid), "ParentImage": parent_image,
                "User": user, "LogonId": logon, **extra}
        return self.add(1, SYSMON, when, data)

    def security_process(self, when, pid, image, command, parent_pid, parent_image, user="alice", logon="0x5555"):
        return self.add(4688, "Security", when, {"NewProcessId": hex(pid), "NewProcessName": image, "CommandLine": command,
                                                 "ProcessId": hex(parent_pid), "ParentProcessName": parent_image,
                                                 "SubjectUserName": user, "SubjectUserSid": "S-1-5-21-1-2-3-1001",
                                                 "SubjectLogonId": logon})

    def logon(self, when, user, logon_id, logon_type="3", ip="203.0.113.7", success=True):
        data = {"TargetUserName": user, "TargetDomainName": "LAB", "TargetLogonId": logon_id, "LogonType": logon_type,
                "IpAddress": ip, "TargetUserSid": "S-1-5-21-1-2-3-1001", "WorkstationName": "SYNTH-REMOTE"}
        return self.add(4624 if success else 4625, "Security", when, data)


def guid(n: int) -> str:
    return f"{n:08x}-0000-0000-0000-000000000000"
