"""Continuous Windows Event Log collection (Griffendo v3).

Replaces the v1/v2 behaviour of reading each log once at launch:

* Each channel keeps a persistent cursor (the last EventRecordID read) in
  collector.db, so new events are picked up every few seconds and a restart
  resumes where it stopped instead of re-reading the whole log.
* New ("live") events are read first on every pass.  History is read
  separately, newest first, in bounded chunks ("backfill"), so the most recent
  part of the 7-day window appears first and backfill never delays live events.
* Events are spooled to disk before delivery and removed only after the
  receiver acknowledges them, so an interrupted batch is re-sent, not lost.
  The receiver deduplicates, so a re-send never creates duplicates.
* Missing record numbers between two reads (log wrapped or cleared while the
  collector was not looking) are counted and reported, never hidden.
* Failures on one channel back off and are reported; other channels continue.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sqlite3
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from .sources import SourceError, open_source

VERSION = "0.3.0"
BASE_CHANNELS = ("System", "Security", "Setup", "Application")
CHANNEL_NAME = re.compile(r"^[A-Za-z0-9 ._()/\-]{1,255}$")
_TIME = re.compile(r'<TimeCreated SystemTime=[\'"]([^\'"]+)[\'"]')
_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _env_float(name: str, default: float, minimum: float = 0.1) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


INTERVAL_SECONDS = _env_float("WINLOG_INTERVAL_SECONDS", 2.0)
LIVE_BATCH = _env_int("WINLOG_LIVE_BATCH", 2000, 1)
BACKFILL_BATCH = _env_int("WINLOG_BACKFILL_BATCH", 2000, 1)
DELIVERY_BATCH = _env_int("WINLOG_BATCH_SIZE", 5000, 1)
MAX_SPOOL_EVENTS = _env_int("WINLOG_MAX_SPOOL_EVENTS", 100000, 1000)
BASE_LOOKBACK_HOURS = _env_int("WINLOG_BACKFILL_HOURS", 336)            # 14 days for the original four logs
SUPPLEMENTARY_LOOKBACK_HOURS = _env_int("WINLOG_SUPPLEMENTARY_LOOKBACK_HOURS", 192)   # 8 days for added logs
CONFIG_REFRESH_SECONDS = 30
HEALTH_SECONDS = 10

# The collector running in this process (set while ContinuousCollector.run() is active).  The dashboard's
# manual Refresh asks it for an immediate pass through request_collection(); nothing else uses it.
ACTIVE: "ContinuousCollector | None" = None


def request_collection(timeout: float = 20.0) -> dict[str, Any] | None:
    """Ask the in-process collector for an immediate pass and wait for it.  None if no collector is running."""
    collector = ACTIVE
    if collector is None:
        return None
    return collector.request_pass(timeout)
LOG_INFO_SECONDS = 600


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def state_dir() -> Path | None:
    configured = os.getenv("GRIFFENDO_STATE_DIR")
    if configured is not None:
        return None if configured.strip().lower() in ("", "none", "memory") else Path(configured)
    if sys.platform == "win32" and os.getenv("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Griffendo"
    return Path.home() / ".griffendo"


def event_key(hostname: str, channel: str, record: int, xml: str) -> str:
    """Stable identity from source identifiers (host, channel, record number, event time, ID), independent of
    how the XML was rendered.  Time is included so records renumbered after a log clear stay distinct."""
    when = _TIME.search(xml)
    eid = _EVENT_ID.search(xml)
    if when and eid:
        basis = f"{hostname}|{channel}|{record}|{when.group(1)}|{eid.group(1)}"
    else:
        basis = f"{hostname}|{channel}|{record}|{xml}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    match = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?Z?$", value.strip())
    if not match:
        return None
    fraction = (match.group(3) or ".0")[1:7].ljust(6, "0")
    return datetime.fromisoformat(f"{match.group(1)}T{match.group(2)}.{fraction}+00:00")


class Endpoint:
    """Receiver URL handling with the original transport rules (HTTPS for remote, no disabled verification)."""

    def __init__(self):
        self.ingest = os.getenv("LOGPLATFORM_URL", "https://localhost:8000/api/ingest")
        self.token = os.getenv("LOGPLATFORM_TOKEN")
        if not self.token:
            raise RuntimeError("Set LOGPLATFORM_TOKEN before starting the agent")
        parsed = urlsplit(self.ingest)
        if parsed.scheme not in ("http", "https"):
            raise RuntimeError("LOGPLATFORM_URL must use HTTP or HTTPS")
        if parsed.scheme == "http":
            host = (parsed.hostname or "").lower()
            if host not in ("localhost", "127.0.0.1", "::1") and not host.startswith("127."):
                raise RuntimeError("Plain HTTP is permitted only for localhost; use HTTPS for remote receivers")
        self.verify = os.getenv("LOGPLATFORM_CA", "True")
        if self.verify.lower() == "false":
            raise RuntimeError("Certificate verification cannot be disabled")
        base = self.ingest.rsplit("/ingest", 1)[0]
        self.status = os.getenv("LOGPLATFORM_STATUS_URL") or base + "/collector/status"
        self.config = base + "/collector/config"
        self.headers = {"Authorization": f"Bearer {self.token}"}


class ContinuousCollector:
    def __init__(self, source=None, session: requests.Session | None = None, hostname: str | None = None,
                 folder: Path | None | str = "default", static_channels: list[str] | None = None,
                 interval: float = INTERVAL_SECONDS, clock=time.monotonic):
        self.hostname = hostname or platform.node()
        self.session = session or requests.Session()
        self.endpoint = Endpoint()
        self.notice = None
        if source is None:
            source, self.notice = open_source(os.getenv("WINLOG_BACKEND", "auto"))
        self.source = source
        self.interval = interval
        self.clock = clock
        folder = state_dir() if folder == "default" else folder
        self.db_path = (Path(folder) / "collector.db") if folder else None
        if self.db_path:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.db_path) if self.db_path else ":memory:", timeout=30, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS channel_state(channel TEXT PRIMARY KEY, state_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS spool(
                id TEXT PRIMARY KEY, channel TEXT NOT NULL, record_id INTEGER NOT NULL, xml TEXT NOT NULL,
                priority INTEGER NOT NULL, phase TEXT NOT NULL, collected_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_spool_order ON spool(priority);
            """
        )
        self.agent_id = self._agent_id()
        self.static_channels = [c for c in (static_channels or []) if CHANNEL_NAME.match(c)]
        self.server_channels: list[str] = []
        self.channels: dict[str, dict[str, Any]] = {}
        self.latency: dict[str, deque] = {}
        self.started_at = utc_iso()
        self.delivery_batch = DELIVERY_BATCH
        self.last_delivery_at = None
        self.last_error = None
        self.last_error_at = None
        self.delivered_total = 0
        self.read_total = 0
        self.rate_window: deque = deque(maxlen=120)
        self._next_config = 0.0
        self._next_health = 0.0
        self._next_log_info = 0.0
        self.log_info: dict[str, dict[str, Any]] = {}
        self.store_id: str | None = None
        # Manual refresh support: a woken, forced pass that ignores retry back-off.
        self._wake = threading.Event()
        self._pass_cond = threading.Condition()
        self._pass_started = 0
        self._pass_finished = 0
        self._force_next = False
        self._last_pass: dict[str, Any] | None = None
        self._pass_errors: list[str] = []
        self._load_states()

    # ------------------------------------------------------------------ persistence
    def _agent_id(self) -> str:
        configured = os.getenv("WINLOG_AGENT_ID")
        if configured:
            return configured
        row = self.db.execute("SELECT value FROM metadata WHERE key = 'agent_id'").fetchone()
        if row:
            return row[0]
        value = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"griffendo-agent:{self.hostname}"))
        with self.db:
            self.db.execute("INSERT INTO metadata(key, value) VALUES ('agent_id', ?)", (value,))
        return value

    def _load_states(self) -> None:
        for channel, raw in self.db.execute("SELECT channel, state_json FROM channel_state"):
            self.channels[channel] = json.loads(raw)
        row = self.db.execute("SELECT value FROM metadata WHERE key = 'receiver_store_id'").fetchone()
        self.store_id = row[0] if row else None

    def _save_state(self, channel: str) -> None:
        self.db.execute("INSERT INTO channel_state(channel, state_json) VALUES (?, ?) "
                        "ON CONFLICT(channel) DO UPDATE SET state_json = excluded.state_json",
                        (channel, json.dumps(self.channels[channel], separators=(",", ":"))))

    def spool_size(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM spool").fetchone()[0]

    # ------------------------------------------------------------------ configuration
    def wanted_channels(self) -> list[str]:
        result = list(BASE_CHANNELS)
        for name in [*self.static_channels, *self.server_channels]:
            if name.lower() not in {item.lower() for item in result} and CHANNEL_NAME.match(name):
                result.append(name)
        return result

    def lookback_hours(self, channel: str) -> int:
        return BASE_LOOKBACK_HOURS if channel in BASE_CHANNELS else SUPPLEMENTARY_LOOKBACK_HOURS

    def refresh_config(self) -> None:
        try:
            response = self.session.get(self.endpoint.config, headers=self.endpoint.headers,
                                        verify=self.endpoint.verify, timeout=(5, 30))
            response.raise_for_status()
            config = response.json()
        except (requests.RequestException, ValueError):
            return   # older receiver or temporarily unreachable: keep the current list
        self.server_channels = [c for c in config.get("channels") or [] if isinstance(c, str) and CHANNEL_NAME.match(c)]
        limit = config.get("max_ingest_events")
        if isinstance(limit, int) and limit > 0:
            self.delivery_batch = min(self.delivery_batch, limit)
        store_id = config.get("store_id")
        if store_id and store_id != self.store_id:
            # The receiver's event store is new (first run, deleted database, or memory mode): re-read history.
            if self.store_id is not None or self.channels:
                with self.db:
                    self.db.execute("DELETE FROM channel_state")
                self.channels.clear()
            self.store_id = store_id
            with self.db:
                self.db.execute("INSERT INTO metadata(key, value) VALUES ('receiver_store_id', ?) "
                                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (store_id,))

    # ------------------------------------------------------------------ channel work
    def _fresh_state(self, channel: str) -> dict[str, Any]:
        return {"channel": channel, "initialized": False, "live_cursor": 0, "backfill_upper": 0,
                "backfill": "pending", "backfill_reached": None, "state": "ok", "detail": None,
                "collected": 0, "last_success_at": None, "last_error_at": None, "last_error": None,
                "records_lost": 0, "lost_detail": None, "failures": 0, "retry_at": 0.0,
                "lookback_hours": self.lookback_hours(channel), "watermark": None}

    def _error(self, state: dict[str, Any], error: SourceError) -> None:
        state.update(state=error.kind, detail=str(error)[:2000], last_error=str(error)[:2000], last_error_at=utc_iso())
        state["failures"] = state.get("failures", 0) + 1
        state["retry_at"] = self.clock() + min(300, self.interval * (2 ** min(state["failures"], 7)))
        text = str(error)
        prefix = f"{state['channel']}: "   # source messages usually name the channel already
        self.last_error, self.last_error_at = (text if text.startswith(prefix) else prefix + text), utc_iso()
        self._pass_errors.append(self.last_error[:500])

    def _ok(self, state: dict[str, Any], detail: str | None = None) -> None:
        state.update(state="ok", detail=detail, failures=0, retry_at=0.0, last_success_at=utc_iso())

    def _spool(self, channel: str, events: list[dict[str, Any]], phase: str) -> None:
        now = utc_iso()
        priority = 0 if phase == "live" else 1
        rows = [(event_key(self.hostname, channel, event["record_id"], event["xml"]), channel, event["record_id"],
                 event["xml"], priority, phase, now) for event in events]
        self.db.executemany("INSERT OR IGNORE INTO spool(id, channel, record_id, xml, priority, phase, collected_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        self.read_total += len(events)
        if phase == "live":
            samples = self.latency.setdefault(channel, deque(maxlen=500))
            collected = datetime.now(timezone.utc)
            for event in events:
                when = _TIME.search(event["xml"])
                occurred = _parse(when.group(1)) if when else None
                if occurred:
                    samples.append(max(0.0, (collected - occurred).total_seconds()))

    def _initialize(self, channel: str, state: dict[str, Any]) -> None:
        newest = self.source.newest_record(channel)
        state.update(initialized=True, watermark=newest)
        if newest is None:
            state.update(live_cursor=0, backfill="not_needed", backfill_upper=0)
            self._mark_empty(channel, state)
        else:
            state.update(live_cursor=newest, backfill_upper=newest, backfill="running")
            self._ok(state)

    def _mark_empty(self, channel: str, state: dict[str, Any]) -> None:
        """An empty log is monitored if it is enabled; a disabled log cannot produce events at all."""
        enabled = (self.log_info.get(channel) or {}).get("enabled")
        if enabled is True:
            self._ok(state, "Log is enabled and currently holds no events.")
        elif enabled is False:
            self._ok(state)
            state.update(state="empty", detail="Log is disabled, so it records nothing (enable it in Event Viewer to monitor it).")
        else:
            self._ok(state)
            state.update(state="empty", detail="The log has no events (it may be empty or disabled).")

    def _read_live(self, channel: str, state: dict[str, Any]) -> int:
        events, newest = self.source.read_after(channel, state["live_cursor"], LIVE_BATCH)
        cursor = state["live_cursor"]
        if not events and newest is not None and cursor and newest < cursor:
            # Record numbers went backwards: the log was cleared.  Start again from its first record.
            state["lost_detail"] = f"Log cleared or recreated around {utc_iso()}; reading restarted from record 1."
            state["live_cursor"] = 0
            self._ok(state)
            return self._read_live(channel, state)      # read the new records now, not on the next pass
        if newest is None and not events:
            state["live_cursor"] = 0
            self._mark_empty(channel, state)
            return 0
        if events:
            first = events[0]["record_id"]
            if cursor and first > cursor + 1:
                missing = first - cursor - 1
                state["records_lost"] = state.get("records_lost", 0) + missing
                state["lost_detail"] = (f"{state['records_lost']} record(s) overwritten or cleared before they could be "
                                        f"read; latest gap #{cursor + 1}-#{first - 1} detected {utc_iso()}")
            with self.db:
                self._spool(channel, events, "live")
                state["live_cursor"] = max(event["record_id"] for event in events)
                state["collected"] = state.get("collected", 0) + len(events)
                self._ok(state)
                self._save_state(channel)
        else:
            self._ok(state)
        return len(events)

    def _read_backfill(self, channel: str, state: dict[str, Any]) -> int:
        if state.get("backfill") != "running":
            return 0
        upper = state["backfill_upper"]
        lookback_ms = state.get("lookback_hours", 0) * 3_600_000
        events = self.source.read_before(channel, upper, BACKFILL_BATCH, lookback_ms) if upper > 0 else []
        with self.db:
            if events:
                self._spool(channel, events, "backfill")
                state["backfill_upper"] = min(event["record_id"] for event in events) - 1
                state["collected"] = state.get("collected", 0) + len(events)
                times = [_TIME.search(event["xml"]) for event in events]
                oldest = min((match.group(1) for match in times if match), default=None)
                if oldest and (not state.get("backfill_reached") or oldest < state["backfill_reached"]):
                    state["backfill_reached"] = oldest
            if len(events) < BACKFILL_BATCH or state["backfill_upper"] <= 0:
                state["backfill"] = "complete"
            self._ok(state, state.get("detail") if state.get("state") == "ok" else None)
            self._save_state(channel)
        return len(events)

    # ------------------------------------------------------------------ delivery & health
    def deliver(self, limit_batches: int = 20) -> int:
        sent = 0
        for _ in range(limit_batches):
            rows = self.db.execute("SELECT id, channel, record_id, xml, phase, collected_at FROM spool "
                                   "ORDER BY priority, rowid LIMIT ?", (self.delivery_batch,)).fetchall()
            if not rows:
                break
            payload = {"agent_id": self.agent_id, "hostname": self.hostname, "os_name": "Windows",
                       "events": [{"id": r[0], "channel": r[1], "record_id": r[2], "xml": r[3], "phase": r[4],
                                   "collected_at": r[5]} for r in rows]}
            try:
                response = self.session.post(self.endpoint.ingest, json=payload, headers=self.endpoint.headers,
                                             verify=self.endpoint.verify, timeout=(5, 120))
                if response.status_code in (413, 422) and len(rows) > 1:
                    self.delivery_batch = max(1, len(rows) // 2)   # receiver refused the size: shrink and retry
                    continue
                response.raise_for_status()
                if response.json().get("accepted") != len(rows):
                    raise RuntimeError("Receiver acknowledgement did not match the sent batch")
            except (requests.RequestException, RuntimeError, ValueError) as error:
                self.last_error, self.last_error_at = f"delivery: {error}", utc_iso()
                self._pass_errors.append(self.last_error[:500])
                break   # events stay spooled; retried on the next pass
            with self.db:
                self.db.executemany("DELETE FROM spool WHERE id = ?", [(r[0],) for r in rows])
            sent += len(rows)
            self.delivered_total += len(rows)
            self.last_delivery_at = utc_iso()
            self.rate_window.append((time.monotonic(), len(rows)))
        return sent

    def _latency_summary(self, channel: str) -> dict[str, Any] | None:
        samples = sorted(self.latency.get(channel) or [])
        if not samples:
            return None
        pick = lambda q: round(samples[min(len(samples) - 1, int(q * len(samples)))], 2)  # noqa: E731
        return {"event_to_collect_seconds_p50": pick(0.5), "event_to_collect_seconds_p95": pick(0.95),
                "event_to_collect_seconds_max": round(samples[-1], 2), "samples": len(samples)}

    def report(self) -> None:
        now = time.monotonic()
        recent = [(t, n) for t, n in self.rate_window if now - t <= 60]
        rate = round(sum(n for _, n in recent) / 60, 1) if recent else 0.0
        channels = []
        for name in self.wanted_channels():
            state = self.channels.get(name)
            if not state:
                continue
            channels.append({
                "channel": name, "state": state["state"], "detail": state.get("detail"),
                "watermark": state.get("watermark"), "collected": state.get("collected"),
                "lookback_hours": state.get("lookback_hours"), "last_success_at": state.get("last_success_at"),
                "last_error_at": state.get("last_error_at"), "last_error": state.get("last_error"),
                "backfill": state.get("backfill"), "backfill_reached": state.get("backfill_reached"),
                "live_cursor": state.get("live_cursor"), "records_lost": state.get("records_lost") or 0,
                "lost_detail": state.get("lost_detail"), "log": self.log_info.get(name),
                "latency": self._latency_summary(name),
            })
        payload = {"agent_id": self.agent_id, "hostname": self.hostname, "channels": channels,
                   "backend": getattr(self.source, "name", "unknown"), "version": VERSION, "mode": "continuous",
                   "started_at": self.started_at, "interval_seconds": self.interval, "spool_size": self.spool_size(),
                   "last_delivery_at": self.last_delivery_at, "last_error": self.last_error,
                   "last_error_at": self.last_error_at,
                   "stats": {"delivered_total": self.delivered_total, "read_total": self.read_total,
                             "delivered_per_second_last_minute": rate, "delivery_batch": self.delivery_batch,
                             "notice": self.notice}}
        try:
            self.session.post(self.endpoint.status, json=payload, headers=self.endpoint.headers,
                              verify=self.endpoint.verify, timeout=(5, 30)).raise_for_status()
        except requests.RequestException:
            pass

    # ------------------------------------------------------------------ main loop
    def run_once(self, force: bool = False) -> dict[str, Any]:
        """One pass: live reads for every channel, delivery, then a bounded slice of backfill.

        force=True (manual refresh) also retries channels that are waiting out an error back-off."""
        now = self.clock()
        self._pass_errors = []
        if force:
            for state in self.channels.values():
                state["retry_at"] = 0.0
            self._next_health = 0
        if now >= self._next_config:
            self.refresh_config()
            self._next_config = now + CONFIG_REFRESH_SECONDS
        channels = self.wanted_channels()
        if now >= self._next_log_info:
            self._next_log_info = now + LOG_INFO_SECONDS
            try:
                self.log_info.update(self.source.log_info(channels))
            except Exception:   # metadata is optional; coverage then says retention could not be confirmed
                pass
        live = backfill = 0
        read_ok: list[str] = []
        read_failed: list[str] = []       # errors: access denied, read failures
        read_missing: list[str] = []      # the log does not exist or is disabled on this computer
        for channel in channels:
            state = self.channels.setdefault(channel, self._fresh_state(channel))
            if state.get("retry_at", 0) > now:
                continue
            try:
                if not state.get("initialized"):
                    self._initialize(channel, state)
                    with self.db:
                        self._save_state(channel)
                if self.spool_size() < MAX_SPOOL_EVENTS:
                    live += self._read_live(channel, state)
                read_ok.append(channel)
            except SourceError as error:
                self._error(state, error)
                (read_missing if error.kind in ("unavailable", "disabled") else read_failed).append(channel)
        self.deliver()
        for channel in channels:
            state = self.channels.get(channel)
            if not state or state.get("retry_at", 0) > now or not state.get("initialized"):
                continue
            if self.spool_size() >= MAX_SPOOL_EVENTS:
                break
            try:
                backfill += self._read_backfill(channel, state)
            except SourceError as error:
                self._error(state, error)
        delivered = self.deliver()
        if now >= self._next_health:
            self._next_health = now + HEALTH_SECONDS
            self.report()
        return {"live": live, "backfill": backfill, "delivered": delivered, "spool": self.spool_size(),
                "channels_read": read_ok, "channels_failed": read_failed, "channels_missing": read_missing,
                "errors": list(self._pass_errors),
                "backend": self.source.name}

    def request_pass(self, timeout: float = 20.0) -> dict[str, Any]:
        """Called from another thread (manual refresh): run a forced pass as soon as possible and wait for it.

        Only passes that START after the request count, so the result always reflects the request."""
        deadline = time.monotonic() + timeout
        with self._pass_cond:
            target = self._pass_started + 1
            self._force_next = True
        self._wake.set()
        with self._pass_cond:
            while self._pass_finished < target:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"state": "timeout", "detail": f"The collector did not finish a pass within {timeout:g} s."}
                self._pass_cond.wait(remaining)
            return dict(self._last_pass or {}, state="done")

    def run(self, stop: threading.Event | None = None, max_passes: int | None = None) -> None:
        global ACTIVE
        stop = stop or threading.Event()
        passes = 0
        ACTIVE = self
        try:
            while not stop.is_set():
                with self._pass_cond:
                    self._pass_started += 1
                    number = self._pass_started
                    force, self._force_next = self._force_next, False
                try:
                    result = self.run_once(force=force)
                except Exception as error:   # keep collecting; the error is reported to the dashboard
                    self.last_error, self.last_error_at = f"collector pass: {error}", utc_iso()
                    result = {"live": 0, "backfill": 0, "delivered": 0, "spool": 0, "channels_read": [],
                              "channels_failed": [], "errors": [self.last_error], "backend": self.source.name}
                with self._pass_cond:
                    self._pass_finished = number
                    self._last_pass = dict(result, number=number, forced=force, finished_at=utc_iso())
                    self._pass_cond.notify_all()
                passes += 1
                if max_passes is not None and passes >= max_passes:
                    break
                busy = result["backfill"] or result["live"] >= LIVE_BATCH or result["spool"]
                # Sleep until the next pass, a manual-refresh wake-up or stop (checked in short slices).
                until = time.monotonic() + (0.05 if busy else self.interval)
                while not stop.is_set() and not self._wake.is_set():
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        break
                    self._wake.wait(min(remaining, 0.25))
                self._wake.clear()
        finally:
            if ACTIVE is self:
                ACTIVE = None
            self._next_health = 0
            self.report()


def run_continuous(stop: threading.Event | None = None) -> None:
    if sys.platform != "win32":
        raise SystemExit("The collection agent must run on Windows.")
    static = [name.strip() for name in os.getenv("WINLOG_CHANNELS", "").split(";") if name.strip()]
    collector = ContinuousCollector(static_channels=static)
    print(f"WinLog agent {collector.agent_id} on {collector.hostname}; backend {collector.source.name}; "
          f"polling every {collector.interval:g}s" + (f" ({collector.notice})" if collector.notice else ""))
    collector.run(stop)
