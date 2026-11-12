"""An in-memory stand-in for Windows Event Log channels (SYNTHETIC data) with the same
interface as agent.sources.NativeSource / PowerShellSource, so the whole collection
pipeline can be exercised without Windows."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from agent.sources import SourceError

import synthetic


class FakeLog:
    name = "fake"

    def __init__(self):
        self.logs: dict[str, list[dict]] = {}
        self.next_id: dict[str, int] = {}
        self.failures: dict[str, SourceError] = {}
        self.lock = threading.Lock()
        self.calls = 0

    # ------------------------------------------------------------ test controls
    def write(self, channel: str, event_id: int, when: datetime | None = None, data=None, provider=None, count=1):
        with self.lock:
            records = self.logs.setdefault(channel, [])
            for _ in range(count):
                record = self.next_id.get(channel, 1)
                self.next_id[channel] = record + 1
                xml = synthetic.event_xml(event_id, channel, when or datetime.now(timezone.utc), record, data=data,
                                          provider=provider)
                records.append({"record_id": record, "xml": xml, "when": when or datetime.now(timezone.utc)})
            return self.next_id[channel] - 1

    def overwrite_oldest(self, channel: str, count: int):
        with self.lock:
            del self.logs[channel][:count]

    def clear(self, channel: str):
        with self.lock:
            self.logs[channel] = []
            self.next_id[channel] = 1

    def fail(self, channel: str, kind: str | None, message: str = "synthetic failure"):
        if kind is None:
            self.failures.pop(channel, None)
        else:
            self.failures[channel] = SourceError(kind, f"{channel}: {message}")

    # ------------------------------------------------------------ source interface
    def _check(self, channel):
        self.calls += 1
        if channel in self.failures:
            raise self.failures[channel]
        if channel not in self.logs:
            raise SourceError("unavailable", f"{channel}: There is not an event log on the localhost computer that matches")

    def newest_record(self, channel):
        self._check(channel)
        records = self.logs[channel]
        return records[-1]["record_id"] if records else None

    def read_after(self, channel, cursor, limit):
        self._check(channel)
        with self.lock:
            records = [r for r in self.logs[channel] if r["record_id"] > cursor][:limit]
            newest = self.logs[channel][-1]["record_id"] if self.logs[channel] else None
        return [{"record_id": r["record_id"], "xml": r["xml"]} for r in records], newest

    def read_before(self, channel, upper, limit, lookback_ms=0):
        self._check(channel)
        cutoff = datetime.now(timezone.utc) - timedelta(milliseconds=lookback_ms) if lookback_ms else None
        with self.lock:
            records = [r for r in reversed(self.logs[channel])
                       if r["record_id"] <= upper and (cutoff is None or r["when"] >= cutoff)][:limit]
        return [{"record_id": r["record_id"], "xml": r["xml"]} for r in records]

    def log_info(self, channels):
        return {c: {"enabled": True, "mode": "Circular", "max_bytes": 20971520, "file_bytes": 1024,
                    "record_count": len(self.logs[c]), "is_full": False,
                    "oldest_record": self.logs[c][0]["record_id"] if self.logs[c] else 0}
                for c in channels if c in self.logs}
