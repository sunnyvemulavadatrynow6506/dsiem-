"""State manager: sliding windows, process lineage and logon sessions for the local host.

Everything here is bounded:
  * every window keeps at most GRIFFENDO_STATE_MAX_PER_KEY entries and drops entries older than its TTL;
  * the number of keys per window family is capped (least recently used keys are evicted);
  * process and logon tables expire entries GRIFFENDO_PROCESS_TTL_HOURS (default 24) after the
    process / logon ended (or started, when no end event was seen) and are capped in size.

Process identity never relies on the PID alone: Sysmon's ProcessGuid when present,
otherwise ``pid:<pid>@<creation time>`` from Security 4688, and PID lookups pick the
process with that PID that existed at the event's time (PID reuse safe).

State is rebuilt after a restart by replaying the stored events of the longest
correlation window (service.py), so nothing here needs its own persistence.
"""
from __future__ import annotations

import bisect
import os
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Iterable

from ...settings import env_int, parse_time


def epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    parsed = value if isinstance(value, datetime) else parse_time(value)
    return parsed.timestamp() if parsed else 0.0


class Window:
    """Time-sorted entries for one key (out-of-order inserts allowed)."""

    __slots__ = ("times", "items")

    def __init__(self) -> None:
        self.times: list[float] = []
        self.items: list[Any] = []

    def add(self, t: float, item: Any, cap: int) -> None:
        index = bisect.bisect_right(self.times, t)
        self.times.insert(index, t)
        self.items.insert(index, item)
        if len(self.times) > cap:
            del self.times[0]
            del self.items[0]

    def expire(self, before: float) -> None:
        index = bisect.bisect_left(self.times, before)
        if index:
            del self.times[:index]
            del self.items[:index]

    def between(self, start: float, end: float) -> list[tuple[float, Any]]:
        lo = bisect.bisect_left(self.times, start)
        hi = bisect.bisect_right(self.times, end)
        return list(zip(self.times[lo:hi], self.items[lo:hi]))

    def __len__(self) -> int:
        return len(self.times)


class WindowFamily:
    """Keyed windows with a TTL (seconds, relative to the newest event time seen) and an LRU key cap."""

    def __init__(self, ttl: float, max_keys: int | None = None, max_per_key: int | None = None):
        self.ttl = ttl
        self.max_keys = max_keys or env_int("GRIFFENDO_STATE_MAX_KEYS", 50000, 100)
        self.max_per_key = max_per_key or env_int("GRIFFENDO_STATE_MAX_PER_KEY", 5000, 10)
        self.windows: OrderedDict[Any, Window] = OrderedDict()
        self.newest = 0.0
        self.evicted = 0

    def add(self, key: Any, t: float, item: Any) -> Window:
        window = self.windows.get(key)
        if window is None:
            window = self.windows[key] = Window()
            if len(self.windows) > self.max_keys:
                self.windows.popitem(last=False)
                self.evicted += 1
        else:
            self.windows.move_to_end(key)
        window.add(t, item, self.max_per_key)
        if t > self.newest:
            self.newest = t
        window.expire(self.newest - self.ttl)
        return window

    def get(self, key: Any) -> Window | None:
        return self.windows.get(key)

    def purge(self) -> None:
        cutoff = self.newest - self.ttl
        for key in [k for k, w in self.windows.items() if not w.times or w.times[-1] < cutoff]:
            del self.windows[key]

    def size(self) -> int:
        return sum(len(w) for w in self.windows.values())


class ProcessTable:
    """Process records keyed by identity, with a PID index for lineage lookups."""

    def __init__(self) -> None:
        self.ttl = env_int("GRIFFENDO_PROCESS_TTL_HOURS", 24, 1) * 3600
        self.cap = env_int("GRIFFENDO_PROCESS_MAX", 200000, 1000)
        self.records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.by_pid: dict[int, list[tuple[float, str]]] = {}
        self.newest = 0.0

    @staticmethod
    def identity(guid: str | None, pid: int | None, start: float) -> str | None:
        if guid:
            return guid
        if pid is None:
            return None
        return f"pid:{pid}@{int(start)}"

    def started(self, ev: dict[str, Any], t: float) -> str | None:
        guid = ev.get("process.entity_id")
        pid = ev.get("process.pid")
        key = self.identity(guid, pid, t)
        if key is None:
            return None
        parent = self.resolve(ev.get("process.parent.entity_id"), ev.get("process.parent.pid"), t)
        record = {"id": key, "pid": pid, "name": ev.get("process.name"), "executable": ev.get("process.executable"),
                  "command_line": ev.get("process.command_line"), "start": t, "end": None,
                  "parent": parent, "parent_name": ev.get("process.parent.name"),
                  "user": ev.get("user.name"), "logon": ev.get("winlog.logon.id"), "event_key": ev.get("_key")}
        self.records[key] = record
        self.records.move_to_end(key)
        if pid is not None:
            entries = self.by_pid.setdefault(pid, [])
            bisect.insort(entries, (t, key))
        self.newest = max(self.newest, t)
        if len(self.records) > self.cap:
            self._evict_oldest()
        return key

    def ended(self, ev: dict[str, Any], t: float) -> None:
        key = self.resolve(ev.get("process.entity_id"), ev.get("process.pid"), t)
        if key and key in self.records:
            self.records[key]["end"] = t

    def resolve(self, guid: str | None, pid: int | None, t: float) -> str | None:
        """Identity of the process (by GUID, else by PID alive at time t)."""
        if guid:
            return guid if guid in self.records else guid
        if pid is None:
            return None
        entries = self.by_pid.get(pid)
        if not entries:
            return None
        index = bisect.bisect_right(entries, (t, "￿")) - 1
        while index >= 0:
            start, key = entries[index]
            record = self.records.get(key)
            if record and (record["end"] is None or record["end"] >= t - 1):
                return key
            index -= 1
        return None

    def ancestors(self, key: str | None, depth: int = 8) -> list[str]:
        chain: list[str] = []
        current = self.records.get(key) if key else None
        while current and len(chain) < depth:
            parent = current.get("parent")
            if not parent or parent in chain:
                break
            chain.append(parent)
            current = self.records.get(parent)
        return chain

    def get(self, key: str | None) -> dict[str, Any] | None:
        return self.records.get(key) if key else None

    def purge(self) -> None:
        cutoff = self.newest - self.ttl
        stale = [k for k, r in self.records.items() if (r["end"] or r["start"]) < cutoff]
        for key in stale:
            self._drop(key)

    def _evict_oldest(self) -> None:
        key, _ = next(iter(self.records.items()))
        self._drop(key)

    def _drop(self, key: str) -> None:
        record = self.records.pop(key, None)
        if record and record["pid"] is not None:
            entries = self.by_pid.get(record["pid"], [])
            entries[:] = [item for item in entries if item[1] != key]
            if not entries:
                self.by_pid.pop(record["pid"], None)


class LogonTable:
    def __init__(self) -> None:
        self.ttl = env_int("GRIFFENDO_LOGON_TTL_HOURS", 24, 1) * 3600
        self.cap = env_int("GRIFFENDO_LOGON_MAX", 50000, 100)
        self.sessions: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.newest = 0.0

    def update(self, ev: dict[str, Any], t: float) -> None:
        code = ev.get("winlog.event_id")
        logon = ev.get("winlog.logon.id")
        if not logon or (ev.get("winlog.channel") or "").lower() != "security":
            return
        logon = str(logon).lower()
        self.newest = max(self.newest, t)
        if code == 4624:
            self.sessions[logon] = {"logon": logon, "user": ev.get("user.name"), "sid": ev.get("user.id"),
                                    "type": ev.get("winlog.logon.type"), "source_ip": ev.get("source.ip"),
                                    "start": t, "end": None, "privileged": False}
            self.sessions.move_to_end(logon)
        elif code == 4672 and logon in self.sessions:
            self.sessions[logon]["privileged"] = True
        elif code in (4634, 4647) and logon in self.sessions:
            self.sessions[logon]["end"] = t
        if len(self.sessions) > self.cap:
            self.sessions.popitem(last=False)

    def get(self, logon: Any) -> dict[str, Any] | None:
        return self.sessions.get(str(logon).lower()) if logon else None

    def purge(self) -> None:
        cutoff = self.newest - self.ttl
        for key in [k for k, s in self.sessions.items() if (s["end"] or s["start"]) < cutoff]:
            del self.sessions[key]


class StateManager:
    """All correlation state of the local host."""

    def __init__(self) -> None:
        self.families: dict[str, WindowFamily] = {}
        self.processes = ProcessTable()
        self.logons = LogonTable()
        self.used: dict[str, OrderedDict[str, None]] = {}
        self.events_seen = 0
        self.max_window = 0.0

    def family(self, name: str, ttl: float) -> WindowFamily:
        family = self.families.get(name)
        if family is None:
            family = self.families[name] = WindowFamily(ttl)
            self.max_window = max(self.max_window, ttl)
        return family

    def observe(self, ev: dict[str, Any], t: float) -> str | None:
        """Update process / logon context; returns the event's own process identity (if any)."""
        self.events_seen += 1
        code = ev.get("winlog.event_id")
        channel = (ev.get("winlog.channel") or "").lower()
        key = None
        if (channel.endswith("sysmon/operational") and code == 1) or (channel == "security" and code == 4688):
            key = self.processes.started(ev, t)
        elif (channel.endswith("sysmon/operational") and code == 5) or (channel == "security" and code == 4689):
            self.processes.ended(ev, t)
        else:
            key = self.processes.resolve(ev.get("process.entity_id"), ev.get("process.pid"), t)
        self.logons.update(ev, t)
        if self.events_seen % 5000 == 0:
            self.purge()
        return key

    def mark_used(self, rule_id: str, keys: Iterable[str]) -> None:
        bucket = self.used.setdefault(rule_id, OrderedDict())
        for key in keys:
            bucket[key] = None
        while len(bucket) > 20000:
            bucket.popitem(last=False)

    def is_used(self, rule_id: str, key: str) -> bool:
        return key in self.used.get(rule_id, ())

    def purge(self) -> None:
        for family in self.families.values():
            family.purge()
        self.processes.purge()
        self.logons.purge()

    def stats(self) -> dict[str, Any]:
        return {"window_entries": sum(f.size() for f in self.families.values()),
                "window_keys": sum(len(f.windows) for f in self.families.values()),
                "evicted_keys": sum(f.evicted for f in self.families.values()),
                "processes": len(self.processes.records), "logon_sessions": len(self.logons.sessions),
                "max_window_seconds": self.max_window}


def window_seconds(value: Any, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


_ = (os, timedelta)
