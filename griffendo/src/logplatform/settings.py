"""Runtime settings and time helpers shared by the receiver modules.

Every value can be changed with an environment variable; defaults were chosen
from the measurements in docs/perf (see docs/REPORT.md).
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def state_dir() -> Path | None:
    """Griffendo's data folder; GRIFFENDO_STATE_DIR=none keeps everything in memory."""
    configured = os.getenv("GRIFFENDO_STATE_DIR")
    if configured is not None:
        return None if configured.strip().lower() in ("", "none", "memory") else Path(configured)
    if sys.platform == "win32" and os.getenv("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Griffendo"
    return Path.home() / ".griffendo"


def storage_mode() -> str:
    """'disk' (default): events, detections and collector state survive restarts. 'memory': v1/v2 behaviour."""
    mode = os.getenv("GRIFFENDO_STORAGE", "disk").strip().lower()
    return "memory" if mode == "memory" or state_dir() is None else "disk"


def retention_days() -> int:
    """Events older than this (by event time) are pruned from the store. 0 keeps everything (up to the row cap)."""
    return env_int("GRIFFENDO_RETENTION_DAYS", 14)


def ui_refresh_seconds() -> int:
    return env_int("GRIFFENDO_UI_REFRESH_SECONDS", 3, minimum=1)


def anomaly_refresh_seconds() -> int:
    """How often the Anomalies view refreshes itself (v4: 60 s).  Collection is not affected."""
    return env_int("GRIFFENDO_ANOMALY_REFRESH_SECONDS", 60, minimum=10)


def refresh_collect_timeout() -> int:
    """How long a manual Refresh waits for the collector to finish its immediate pass."""
    return env_int("GRIFFENDO_REFRESH_TIMEOUT_SECONDS", 20, minimum=2)


def stats_cache_seconds() -> int:
    return env_int("GRIFFENDO_STATS_CACHE_SECONDS", 10)


# --------------------------------------------------------------------------- time
_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value: Any) -> datetime | None:
    """Windows SystemTime / ISO-8601 (7-digit fractions, 'Z', offsets) -> aware UTC datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    match = _TIME.match(value.strip())
    if not match:
        return None
    date, clock, fraction, zone = match.groups()
    fraction = (fraction or ".0")[1:7].ljust(6, "0")
    zone = zone or "Z"
    if zone == "Z":
        zone = "+00:00"
    elif ":" not in zone:
        zone = f"{zone[:3]}:{zone[3:]}"
    try:
        return datetime.fromisoformat(f"{date}T{clock}.{fraction}{zone}").astimezone(timezone.utc)
    except ValueError:
        return None


def iso(value: datetime) -> str:
    """Fixed-width UTC text, so SQL string comparison equals time comparison."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_time(value: Any) -> str | None:
    parsed = parse_time(value)
    return iso(parsed) if parsed else None
