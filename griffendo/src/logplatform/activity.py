"""Home-page activity graph: events per hour over the rolling last 24 hours, by event category (v4).

Categories come only from each event's stored channel name - nothing is inferred:

    Security          channel "Security"
    System            channel "System"
    Application       channel "Application"
    Windows Defender  channel "Microsoft-Windows-Windows Defender/..."
    Other channels    any other channel name (Setup, Sysmon, Task Scheduler, ...; listed in the response)
    Unknown channel   no channel recorded

Window: [now - 24 h, now] on each event's own time (event_time).  Buckets are whole hours of the
viewer's local clock (offset passed by the browser), so the first and last bucket are partial and
marked as such.  Counts are read per minute from the (channel, event_time) index and summed into
buckets here, which keeps the query an index range scan and works for any time-zone offset.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from . import db
from .settings import iso, utc_now

CATEGORIES = (
    ("security", "Security"),
    ("system", "System"),
    ("application", "Application"),
    ("defender", "Windows Defender"),
    ("other", "Other channels"),
    ("unknown", "Unknown channel"),
)


def channel_category(channel: str | None) -> str:
    name = (channel or "").strip().lower()
    if not name:
        return "unknown"
    if name in ("security", "system", "application"):
        return name
    if name.startswith("microsoft-windows-windows defender/"):
        return "defender"
    return "other"


def _floor_local_hour(moment: datetime, offset: timedelta) -> datetime:
    local = moment + offset
    return local.replace(minute=0, second=0, microsecond=0) - offset


def hourly_activity(channels: list[str], now: datetime | None = None, tz_offset_minutes: int = 0) -> dict[str, Any]:
    now = now or utc_now()
    offset = timedelta(minutes=max(-14 * 60, min(14 * 60, int(tz_offset_minutes))))
    start = now - timedelta(hours=24)
    boundaries = [start]
    edge = _floor_local_hour(start, offset) + timedelta(hours=1)
    while edge < now:
        boundaries.append(edge)
        edge += timedelta(hours=1)
    boundaries.append(now)
    buckets = [{"start": iso(lo), "end": iso(hi), "partial": (hi - lo) < timedelta(hours=1), "counts": {}, "total": 0}
               for lo, hi in zip(boundaries, boundaries[1:])]
    per_channel: dict[str, int] = {}
    minute_counts: list[tuple[str, str, int]] = []
    with db.read() as connection:
        for channel in [*channels, None]:
            if channel is None:
                sql = ("SELECT substr(event_time, 1, 16) AS minute, COUNT(*) AS n FROM events "
                       "WHERE (channel IS NULL OR channel = '') AND event_time >= ? AND event_time <= ? GROUP BY minute")
                rows = connection.execute(sql, (iso(start), iso(now))).fetchall()
            else:
                sql = ("SELECT substr(event_time, 1, 16) AS minute, COUNT(*) AS n FROM events "
                       "WHERE channel = ? AND event_time >= ? AND event_time <= ? GROUP BY minute")
                rows = connection.execute(sql, (channel, iso(start), iso(now))).fetchall()
            for row in rows:
                minute_counts.append((channel or "", row["minute"], row["n"]))
    category_totals = {key: 0 for key, _ in CATEGORIES}
    category_channels: dict[str, dict[str, int]] = {key: {} for key, _ in CATEGORIES}
    for channel, minute, count in minute_counts:
        moment = datetime.fromisoformat(minute + ":00+00:00")
        # Index of the bucket containing this minute (the start minute may be partial; event_time filter handled it).
        index = 0 if moment < boundaries[1] else min(len(buckets) - 1,
                                                     1 + int((moment - boundaries[1]).total_seconds() // 3600))
        category = channel_category(channel)
        bucket = buckets[index]
        bucket["counts"][category] = bucket["counts"].get(category, 0) + count
        bucket["total"] += count
        category_totals[category] += count
        name = channel or "(no channel recorded)"
        category_channels[category][name] = category_channels[category].get(name, 0) + count
        per_channel[name] = per_channel.get(name, 0) + count
    return {
        "window_start": iso(start), "window_end": iso(now), "tz_offset_minutes": int(offset.total_seconds() // 60),
        "bucket": "1 hour of local time; first and last buckets are partial",
        "categories": [{"key": key, "label": label, "total": category_totals[key],
                        "channels": dict(sorted(category_channels[key].items(), key=lambda item: -item[1]))}
                       for key, label in CATEGORIES],
        "buckets": buckets, "total": sum(category_totals.values()),
        "basis": "Event time (the time Windows recorded), not the time Griffendo received the event.",
    }
