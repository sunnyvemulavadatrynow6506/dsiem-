"""Poll Windows Event Logs, durably spool raw XML, and deliver batches."""
from __future__ import annotations

import hashlib
import json
import ipaddress
import os
import platform
import re
import sqlite3
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlsplit

import requests


BASE_CHANNELS = ("System", "Security", "Setup", "Application")
# Channel names are embedded in PowerShell single-quoted strings, so only plain
# event-log channel characters are accepted.
_CHANNEL_NAME = re.compile(r"^[A-Za-z0-9 ._()/\-]{1,255}$")


def _configured_channels() -> tuple[str, ...]:
    """WINLOG_CHANNELS (';'-separated) adds channels, e.g. for anomaly rules; the original four are always kept."""
    channels = list(BASE_CHANNELS)
    for name in os.getenv("WINLOG_CHANNELS", "").split(";"):
        name = name.strip()
        if not name or name.lower() in {item.lower() for item in channels}:
            continue
        if not _CHANNEL_NAME.match(name):
            print(f"Ignoring unsupported channel name in WINLOG_CHANNELS: {name!r}", file=sys.stderr)
            continue
        channels.append(name)
    return tuple(channels)


CHANNELS = _configured_channels()
# Added channels only need to cover the anomaly window, so they are read with a
# time bound (default 8 days = 7-day window + 1 day margin; 0 = no bound).  The
# original four channels are read in full, exactly as before.
SUPPLEMENTARY_LOOKBACK_HOURS = max(0, int(os.getenv("WINLOG_SUPPLEMENTARY_LOOKBACK_HOURS", "192")))
MAX_PARALLEL_CHANNELS = max(1, min(len(CHANNELS), int(os.getenv("WINLOG_MAX_PARALLEL_CHANNELS", "6"))))
CHANNEL_STATES: dict[str, dict[str, Any]] = {}
BATCH_SIZE = min(2000, max(len(CHANNELS), int(os.getenv("WINLOG_BATCH_SIZE", "2000"))))
CHANNEL_BATCH_SIZE = min(500, max(1, BATCH_SIZE // len(CHANNELS)))
MAX_SPOOL_EVENTS = int(os.getenv("WINLOG_MAX_SPOOL_EVENTS", "100000"))
REPORTED_CHANNEL_ERRORS: set[str] = set()
AGENT_ID = os.getenv("WINLOG_AGENT_ID")
HOSTNAME = platform.node()


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", timeout=10)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS cursors(channel TEXT PRIMARY KEY, record_id INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS spool(
            id TEXT PRIMARY KEY, channel TEXT NOT NULL, record_id INTEGER NOT NULL, xml TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_spool_order ON spool(channel, record_id);
        """
    )
    return connection


def ensure_agent_id(connection: sqlite3.Connection) -> str:
    global AGENT_ID
    if AGENT_ID:
        return AGENT_ID
    row = connection.execute("SELECT value FROM metadata WHERE key = 'agent_id'").fetchone()
    if row:
        AGENT_ID = row[0]
    else:
        AGENT_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"griffendo-agent:{HOSTNAME}"))
        with connection:
            connection.execute("INSERT INTO metadata(key, value) VALUES ('agent_id', ?)", (AGENT_ID,))
    return AGENT_ID


def initialize_cursors(connection: sqlite3.Connection) -> None:
    with connection:
        for channel in CHANNELS:
            connection.execute(
                "INSERT INTO cursors(channel, record_id) VALUES (?, 0) ON CONFLICT(channel) DO UPDATE SET record_id=0",
                (channel,),
            )


def capture_channel_watermark(channel: str) -> int:
    script = f"""
$ErrorActionPreference = 'Stop'
$recordId = 0
try {{
    $latest = Get-WinEvent -LogName '{channel}' -MaxEvents 1
    if ($latest) {{ $recordId = [long]$latest.RecordId }}
}} catch {{
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
}}
[PSCustomObject]@{{ record_id = $recordId }} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        message = result.stderr.strip() or f"PowerShell exited with {result.returncode}"
        raise RuntimeError(f"{channel}: {message}")
    return int(json.loads(result.stdout).get("record_id", 0))


def lookback_hours(channel: str) -> int:
    return 0 if channel in BASE_CHANNELS else SUPPLEMENTARY_LOOKBACK_HOURS


def _set_state(channel: str, state: str, detail: str | None = None, **extra: Any) -> None:
    entry = CHANNEL_STATES.setdefault(channel, {"channel": channel, "collected": 0})
    entry.update(state=state, detail=detail, lookback_hours=lookback_hours(channel) or None, **extra)


def classify_channel_error(error: BaseException) -> str:
    text = str(error).lower()
    if "not an event log" in text or "no event log" in text or "could not be found" in text:
        return "unavailable"
    if "unauthorized" in text or "access is denied" in text or "access denied" in text:
        return "access_denied"
    return "error"


def load_snapshot_watermarks(connection: sqlite3.Connection) -> dict[str, int | None]:
    row = connection.execute("SELECT value FROM metadata WHERE key = 'snapshot_watermarks'").fetchone()
    if row:
        return json.loads(row[0])

    watermarks = {channel: None for channel in CHANNELS}
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHANNELS, thread_name_prefix="event-watermark") as executor:
        futures = {executor.submit(capture_channel_watermark, channel): channel for channel in CHANNELS}
        for future in as_completed(futures):
            channel = futures[future]
            try:
                watermarks[channel] = future.result()
                if watermarks[channel] > 0:
                    _set_state(channel, "ok", watermark=watermarks[channel])
                else:
                    _set_state(channel, "empty", "The log has no events (it may be empty or disabled).", watermark=0)
            except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                print(f"Cannot snapshot {channel}; skipping it for this run: {error}", file=sys.stderr)
                _set_state(channel, classify_channel_error(error), str(error)[:2000])

    with connection:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES ('snapshot_watermarks', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(watermarks, separators=(",", ":")),),
        )
    return watermarks


def clear_snapshot_watermarks(connection: sqlite3.Connection) -> None:
    with connection:
        connection.execute("DELETE FROM metadata WHERE key = 'snapshot_watermarks'")


def collect_channel(
    channel: str,
    last_record_id: int,
    max_events: int = 250,
    upper_record_id: int | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Use PowerShell's Windows Event Log provider only to retrieve raw XML."""
    hours = lookback_hours(channel)
    time_bound = f" and TimeCreated[timediff(@SystemTime) <= {hours * 3_600_000}]" if hours else ""
    script = f"""
$ErrorActionPreference = 'Stop'
$latest = $null
try {{ $latest = Get-WinEvent -LogName '{channel}' -MaxEvents 1 }} catch {{
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
}}
$upper = if ($latest) {{ [long]$latest.RecordId }} else {{ 0 }}
if ({upper_record_id if upper_record_id is not None else -1} -ge 0) {{ $upper = {upper_record_id if upper_record_id is not None else -1} }}
$reset = $latest -and $latest.RecordId -lt {last_record_id}
$cursor = if ($reset) {{ 0 }} else {{ {last_record_id} }}
$items = @()
try {{
    $items = @(Get-WinEvent -LogName '{channel}' -FilterXPath "*[System[EventRecordID > $cursor and EventRecordID <= $upper{time_bound}]]" -Oldest -MaxEvents {max_events} | ForEach-Object {{
        [PSCustomObject]@{{ record_id = [long]$_.RecordId; xml = $_.ToXml() }}
    }})
}} catch {{
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
}}
[PSCustomObject]@{{ reset = [bool]$reset; events = $items }} | ConvertTo-Json -Compress -Depth 4
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        message = result.stderr.strip() or f"PowerShell exited with {result.returncode}"
        raise RuntimeError(f"{channel}: {message}")
    output = result.stdout.strip()
    if not output:
        return [], False
    decoded = json.loads(output)
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{channel}: unexpected collector response")
    events = decoded.get("events") or []
    return (events if isinstance(events, list) else [events]), bool(decoded.get("reset"))


def collect_and_spool(connection: sqlite3.Connection, watermarks: dict[str, int | None]) -> int:
    pending = connection.execute("SELECT COUNT(*) FROM spool").fetchone()[0]
    if pending >= MAX_SPOOL_EVENTS:
        return 0

    cursors = {}
    for channel in CHANNELS:
        row = connection.execute("SELECT record_id FROM cursors WHERE channel = ?", (channel,)).fetchone()
        cursors[channel] = row[0] if row else 0

    results = {}
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHANNELS, thread_name_prefix="event-channel") as executor:
        futures = {
            executor.submit(
                collect_channel,
                channel,
                cursors[channel],
                CHANNEL_BATCH_SIZE,
                watermarks[channel],
            ): channel
            for channel in CHANNELS
            if watermarks.get(channel) is not None and watermarks[channel] > 0
        }
        for future in as_completed(futures):
            channel = futures[future]
            try:
                results[channel] = future.result()
            except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                if channel not in REPORTED_CHANNEL_ERRORS:
                    print(f"Cannot collect {channel}; continuing with other channels: {error}", file=sys.stderr)
                    REPORTED_CHANNEL_ERRORS.add(channel)
                _set_state(channel, classify_channel_error(error), str(error)[:2000])

    inserted = 0
    remaining = MAX_SPOOL_EVENTS - pending
    for channel in CHANNELS:
        if remaining <= 0:
            break
        result = results.get(channel)
        if result is None:
            continue
        events, reset = result
        try:
            if reset:
                with connection:
                    connection.execute("UPDATE cursors SET record_id = 0 WHERE channel = ?", (channel,))
            events = events[:remaining]
        except (sqlite3.Error, TypeError, ValueError) as error:
            print(f"Cannot prepare {channel} events; continuing with other channels: {error}", file=sys.stderr)
            continue
        if not events:
            next_cursor = watermarks[channel] if reset else max(cursors[channel], watermarks[channel])
            with connection:
                connection.execute(
                    "INSERT INTO cursors(channel, record_id) VALUES (?, ?) ON CONFLICT(channel) DO UPDATE SET record_id=excluded.record_id",
                    (channel, next_cursor),
                )
            continue
        with connection:
            for event in events:
                record_id = int(event["record_id"])
                raw_xml = str(event["xml"])
                stable_key = f"{HOSTNAME}|{channel}|{record_id}|{raw_xml}"
                event_id = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT OR IGNORE INTO spool(id, channel, record_id, xml) VALUES (?, ?, ?, ?)",
                    (event_id, channel, record_id, raw_xml),
                )
            latest = max(int(event["record_id"]) for event in events)
            connection.execute(
                "INSERT INTO cursors(channel, record_id) VALUES (?, ?) ON CONFLICT(channel) DO UPDATE SET record_id=MAX(record_id, excluded.record_id)",
                (channel, latest),
            )
            inserted += len(events)
        if channel in CHANNEL_STATES:
            CHANNEL_STATES[channel]["collected"] = CHANNEL_STATES[channel].get("collected", 0) + len(events)
        remaining -= len(events)
    return inserted


def report_channel_status(session: requests.Session, agent_id: str) -> None:
    """Tell the receiver which channels could be read, so the dashboard never implies coverage it lacks."""
    if not CHANNEL_STATES:
        return
    endpoint = os.getenv("LOGPLATFORM_URL", "https://localhost:8000/api/ingest")
    status_url = os.getenv("LOGPLATFORM_STATUS_URL") or endpoint.rsplit("/ingest", 1)[0] + "/collector/status"
    token = os.getenv("LOGPLATFORM_TOKEN")
    verify = os.getenv("LOGPLATFORM_CA", "True")
    if not token or verify.lower() == "false" or urlsplit(status_url).scheme != urlsplit(endpoint).scheme:
        return
    payload = {"agent_id": agent_id, "hostname": HOSTNAME, "channels": [
        {key: value for key, value in state.items() if key in ("channel", "state", "detail", "watermark", "collected", "lookback_hours")}
        for state in CHANNEL_STATES.values()
    ]}
    try:
        response = session.post(status_url, json=payload, headers={"Authorization": f"Bearer {token}"},
                                verify=verify, timeout=(5, 30))
        response.raise_for_status()
    except requests.RequestException as error:
        # An older receiver without this endpoint must not stop collection.
        print(f"Channel status not reported: {error}", file=sys.stderr)


def deliver(connection: sqlite3.Connection, session: requests.Session, agent_id: str) -> int:
    endpoint = os.getenv("LOGPLATFORM_URL", "https://localhost:8000/api/ingest")
    token = os.getenv("LOGPLATFORM_TOKEN")
    if not token:
        raise RuntimeError("Set LOGPLATFORM_TOKEN before starting the agent")
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme not in ("http", "https"):
        raise RuntimeError("LOGPLATFORM_URL must use HTTP or HTTPS")
    if parsed_endpoint.scheme == "http":
        hostname = parsed_endpoint.hostname or ""
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname.lower() == "localhost"
        if not loopback:
            raise RuntimeError("Plain HTTP is permitted only for localhost; use HTTPS for remote receivers")
    verify = os.getenv("LOGPLATFORM_CA", "True")
    if verify.lower() == "false":
        raise RuntimeError("Certificate verification cannot be disabled")

    rows = connection.execute(
        "SELECT id, channel, record_id, xml FROM spool ORDER BY rowid LIMIT ?", (BATCH_SIZE,)
    ).fetchall()
    payload = {
        "agent_id": agent_id,
        "hostname": HOSTNAME,
        "os_name": "Windows",
        "events": [
            {"id": row[0], "channel": row[1], "record_id": row[2], "xml": row[3]}
            for row in rows
        ],
    }
    response = session.post(
        endpoint,
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
        timeout=(5, 30),
    )
    response.raise_for_status()
    acknowledgement = response.json()
    if acknowledgement.get("accepted") != len(rows):
        raise RuntimeError("Receiver acknowledgement did not match the sent batch")
    if rows:
        with connection:
            connection.executemany("DELETE FROM spool WHERE id = ?", [(row[0],) for row in rows])
    return len(rows)


def transfer_snapshot(
    connection: sqlite3.Connection,
    session: requests.Session,
    agent_id: str,
    watermarks: dict[str, int | None],
) -> tuple[int, int]:
    total_collected = 0
    total_sent = 0
    while True:
        collected = collect_and_spool(connection, watermarks)
        sent = deliver(connection, session, agent_id)
        total_collected += collected
        total_sent += sent
        queued = connection.execute("SELECT COUNT(*) FROM spool").fetchone()[0]
        print(f"Collected {collected}; delivered {sent}; queued {queued}")
        if collected == 0 and queued == 0:
            return total_collected, total_sent


def main(stop=None) -> None:
    """Continuous collection by default (v3).  WINLOG_MODE=snapshot keeps the v1/v2 read-once behaviour."""
    if sys.platform != "win32":
        raise SystemExit("The collection agent must run on Windows.")
    if os.getenv("WINLOG_MODE", "continuous").lower() != "snapshot":
        from .continuous import run_continuous

        run_continuous(stop)
        return
    with connect() as connection, requests.Session() as session:
        agent_id = ensure_agent_id(connection)
        initialize_cursors(connection)
        watermarks = load_snapshot_watermarks(connection)
        print(f"WinLog agent {agent_id} on {HOSTNAME}; channels: {', '.join(CHANNELS)}")
        report_channel_status(session, agent_id)
        try:
            collected, sent = transfer_snapshot(connection, session, agent_id, watermarks)
        except (OSError, RuntimeError, requests.RequestException, sqlite3.Error, json.JSONDecodeError) as error:
            queued = connection.execute("SELECT COUNT(*) FROM spool").fetchone()[0]
            print(f"Snapshot transfer stopped; {queued} event(s) remain safely queued: {error}", file=sys.stderr)
            raise SystemExit(1) from error
        clear_snapshot_watermarks(connection)
        report_channel_status(session, agent_id)
        print(f"Snapshot complete; collected {collected} event(s), delivered {sent} event(s).")


if __name__ == "__main__":
    main()
