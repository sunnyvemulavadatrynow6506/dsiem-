"""HTTP ingestion API and dashboard server."""
from __future__ import annotations

import os
import hmac
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

from . import activity, anomalies, busy, db, settings, timeline as timeline_queries
from . import detection_api
from .detection.engine import queries as detection_queries
from .detection.engine import service as detection_service
from .detection.engine import store as detection_store


# Originally fixed at 2,000 events / 32 MB per request.  Configurable now; the
# default was chosen from measured ingest throughput (docs/perf).
MAX_INGEST_EVENTS = settings.env_int("LOGPLATFORM_MAX_INGEST_EVENTS", 10_000, minimum=1)
MAX_INGEST_BYTES = settings.env_int("LOGPLATFORM_MAX_INGEST_BYTES", 128_000_000, minimum=1_000_000)
APP_VERSION = "0.5.1"
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    WEB_DIR = Path(sys._MEIPASS) / "web"
else:
    WEB_DIR = Path(__file__).resolve().parents[2] / "web"
    if not WEB_DIR.exists():
        WEB_DIR = Path(sys.prefix) / "web"
EVENT_LABELS = {
    ("Security", 4624): "Successful logon",
    ("Security", 4625): "Failed logon",
    ("Security", 4672): "Special privileges assigned",
    ("Security", 4688): "Process created",
    ("System", 7045): "Service installed",
    ("System", 7036): "Service state changed",
}


def event_label(channel: str | None, event_id: int | None, default: str | None) -> str | None:
    """Existing labels first, then the anomaly catalog's name, then the caller's default."""
    return EVENT_LABELS.get((channel, event_id)) or anomalies.rule_name(channel, event_id) or default


def start_detection(start_worker: bool = True):
    """Start the detection engine (v5) and let channel health / collection follow its rules."""
    svc = detection_service.service(start_worker=start_worker and os.getenv("GRIFFENDO_DETECTION_WORKER", "1") != "0")
    anomalies.RULE_CHANNELS = lambda: svc.registry.channels()
    anomalies.RULE_VERSION = lambda: svc.registry.version
    return svc


def _start_detection_background() -> None:
    """Load the rules and rebuild correlation state off the start-up path (the server is already serving)."""
    try:
        start_detection()
        busy.set_phase("ready", detection_ready=True)
    except Exception as error:  # the dashboard keeps working; /api/detections/status reports it
        busy.set_phase(f"detection engine failed to start: {error}")
        return
    _warm_detection_pages()


def _warm_detection_pages() -> None:
    """Compute the counts the first pages ask for, so opening them right after start-up is quick.

    Skipped when the background worker is off (tests and tools drive the engine themselves), and
    stopped as soon as the engine it started with is shut down, so it can never start a new one.
    """
    if os.getenv("GRIFFENDO_DETECTION_WORKER", "1") == "0":
        return
    engine = detection_service.service_if_ready()
    steps = [lambda count=recent: detection_queries.summary(*detection_api.time_range("7d", None, None)[:2], count)
             for recent in (4, 1, 5)]                  # Overview columns, menu badge, Detections page
    steps += [lambda: detection_queries.summary(None, None, 8), detection_queries.rule_stats]   # Endpoint, Rules
    for step in steps:
        if engine is None or detection_service.service_if_ready() is not engine:
            return
        try:
            step()
        except Exception:  # only a warm-up: the pages compute these themselves anyway
            return


@asynccontextmanager
async def lifespan(_: FastAPI):
    busy.set_phase("opening the event database")
    db.initialize()
    detection_store.initialize(tables_only=True)
    anomalies.initialize()
    # v5.1: the dashboard starts serving now; the 1,456 rules load and correlation state is rebuilt
    # in the background (that took 30 s or more on a store with history and kept the page from loading).
    busy.set_phase("loading detection rules", ready=True, detection_ready=False)
    threading.Thread(target=_start_detection_background, name="griffendo-detection-start", daemon=True).start()
    try:
        yield
    finally:
        detection_service.shutdown()
        anomalies.RULE_CHANNELS = None
        anomalies.RULE_VERSION = None
        anomalies.shutdown()
        db.reset_memory()


app = FastAPI(title="Griffendo Windows Event Intelligence", version="0.5.1", lifespan=lifespan)


class _RequestActivity:
    """Plain ASGI middleware: counts API requests in flight so the detection worker can give way."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            return await self.inner(scope, receive, send)
        busy.enter()
        try:
            return await self.inner(scope, receive, send)
        finally:
            busy.leave()


app.add_middleware(_RequestActivity)
app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")
app.include_router(detection_api.router)


class EventEnvelope(BaseModel):
    id: str = Field(min_length=16, max_length=128)
    channel: str = Field(min_length=1, max_length=255)
    record_id: int | None = Field(default=None, ge=0)
    xml: str = Field(min_length=1, max_length=1_000_000)
    collected_at: str | None = Field(default=None, max_length=40)
    phase: str | None = Field(default=None, pattern=r"^(live|backfill|snapshot)$")

    @field_validator("channel")
    @classmethod
    def known_channel(cls, value: str) -> str:
        # Originally System|Security|Setup|Application only; now also the channels
        # named by the anomaly catalog (Defender, WMI-Activity, Sysmon, ...).
        if value not in anomalies.accepted_channels():
            raise ValueError(f"Channel {value!r} is not accepted by this receiver")
        return value


class IngestBatch(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=64)
    events: list[EventEnvelope] = Field(max_length=MAX_INGEST_EVENTS)

    @model_validator(mode="after")
    def limit_batch_bytes(self) -> "IngestBatch":
        if sum(len(event.xml.encode("utf-8")) for event in self.events) > MAX_INGEST_BYTES:
            raise ValueError(f"Event batch exceeds the {MAX_INGEST_BYTES // 1_000_000} MB limit")
        return self


def require_agent_token(authorization: str | None = Header(default=None)) -> None:
    expected = os.getenv("LOGPLATFORM_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="Ingestion token is not configured")
    if not authorization or not hmac.compare_digest(authorization, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, Any]:
    # async: answered on the event loop even when every worker thread is busy.
    return {"status": "ok", "version": APP_VERSION, "phase": busy.STARTUP["phase"],
            "detection_ready": busy.STARTUP["detection_ready"]}


@app.post("/api/ingest", status_code=202, dependencies=[Depends(require_agent_token)])
def ingest(batch: IngestBatch) -> dict[str, int]:
    inserted = db.store_batch(
        batch.agent_id,
        batch.hostname,
        batch.os_name,
        [event.model_dump() for event in batch.events],
    )
    # v5: the detection engine runs in the background (collection is never blocked by detection);
    # new events are evaluated as soon as the worker wakes up.
    if inserted:
        detection_service.service().notify()
    return {"accepted": len(batch.events), "inserted": inserted}


@app.get("/api/overview")
def overview(tz_offset: int = Query(default=0, ge=-840, le=840)) -> dict[str, Any]:
    # Whole-table aggregates are cached for a few seconds instead of being
    # recomputed on every dashboard refresh.  tz_offset (minutes east of UTC, sent by the browser) only
    # aligns the 24-hour graph's buckets to the viewer's local hours.
    data = dict(anomalies._cached("overview", _overview))
    data["activity_24h"] = anomalies._cached(
        f"activity-24h-{tz_offset}-{anomalies.data_version()}",
        lambda: activity.hourly_activity([row["channel"] for row in data["channels"] if row["channel"]],
                                         tz_offset_minutes=tz_offset), ttl=settings.stats_cache_seconds())
    return data


def _overview() -> dict[str, Any]:
    # v5: aggregate tables maintained by triggers (db.AGGREGATE_SQL) replace the full-table scans of v4.
    now = datetime.now(timezone.utc)
    with db.read() as connection:
        events_total = connection.execute("SELECT IFNULL(SUM(n), 0) FROM agg_host").fetchone()[0]
        hosts = connection.execute("SELECT COUNT(DISTINCT hostname) FROM agg_host WHERE n > 0").fetchone()[0]
        process_count = connection.execute("SELECT COUNT(*) FROM agg_process WHERE n > 0").fetchone()[0]
        event_id_count = connection.execute("SELECT COUNT(DISTINCT event_id) FROM agg_event_id WHERE n > 0").fetchone()[0]
        trend = connection.execute(
            "SELECT hour, SUM(n) AS count FROM agg_channel_hour WHERE hour >= ? AND n > 0 GROUP BY hour ORDER BY hour",
            (settings.iso(now - timedelta(hours=24))[:13],)).fetchall()
        event_rows = connection.execute(
            "SELECT event_id, channel, n AS count FROM agg_event_id WHERE n > 0 ORDER BY n DESC LIMIT 10").fetchall()
        channels = connection.execute(
            "SELECT channel, SUM(n) AS count FROM agg_channel_hour WHERE n > 0 GROUP BY channel ORDER BY count DESC"
        ).fetchall()
        processes = connection.execute(
            "SELECT process_name, n AS count FROM agg_process WHERE n > 0 ORDER BY n DESC LIMIT 8").fetchall()
    return {
        "totals": {"events": events_total, "hosts": hosts, "processes": process_count, "event_ids": event_id_count},
        "trend": [dict(row) for row in trend],
        "event_ids": [
            {**dict(row), "label": event_label(row["channel"], row["event_id"], "Windows event")}
            for row in event_rows
        ],
        "channels": [dict(row) for row in channels],
        "processes": [dict(row) for row in processes],
    }


@app.get("/api/events")
def events(
    host: str | None = None,
    channel: str | None = None,
    event_id: int | None = None,
    process: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    range: str | None = Query(default=None, max_length=10),
    start: str | None = Query(default=None, max_length=40),
    end: str | None = Query(default=None, max_length=40),
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    # v5: the time filter runs in SQL on the normalized event time (index idx_events_event_time),
    # so pagination and totals respect it.  start/end are ISO-8601 (the browser converts local input to UTC).
    begin, finish, label = detection_api.time_range(range, start, end, default=None)
    clauses = []
    params = []
    if begin:
        clauses.append("event_time >= ?")
        params.append(begin)
    if finish:
        clauses.append("event_time <= ?")
        params.append(finish)
    for column, value in (("hostname", host), ("channel", channel), ("event_id", event_id)):
        if value is None:
            continue
        clauses.append(f"{column} = ?")
        params.append(value)
    if process:
        clauses.append("process_name LIKE ?")
        params.append(f"%{process}%")
    if q:
        clauses.append("(provider LIKE ? OR username LIKE ? OR command_line LIKE ? OR raw_xml LIKE ?)")
        params.extend([f"%{q}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db.read() as connection:
        # v5: exact totals from the aggregate tables when the filters allow it (no COUNT over the store).
        only = {name for name, value in (("host", host), ("channel", channel), ("event_id", event_id),
                                         ("process", process), ("q", q), ("time", begin or finish)) if value}
        if not only:
            total = connection.execute("SELECT IFNULL(SUM(n), 0) FROM agg_host").fetchone()[0]
        elif only == {"host"}:
            total = connection.execute("SELECT IFNULL(SUM(n), 0) FROM agg_host WHERE hostname = ?", (host,)).fetchone()[0]
        elif only <= {"channel", "event_id"}:
            sql, values = "SELECT IFNULL(SUM(n), 0) FROM agg_event_id WHERE 1 = 1", []
            if channel is not None:
                sql += " AND channel = ?"
                values.append(channel)
            if event_id is not None:
                sql += " AND event_id = ?"
                values.append(event_id)
            total = connection.execute(sql, values).fetchone()[0]
        else:
            total = connection.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM events {where} ORDER BY event_time DESC, id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    items = []
    for row in rows:
        item = db.row_to_event(row)
        item["event_label"] = event_label(row["channel"], row["event_id"], "Windows event")
        items.append(item)
    return {"items": items, "total": total, "limit": limit, "offset": offset,
            "range": {"start": begin, "end": finish, "label": label}}


@app.get("/api/events/{event_key}")
def event_detail(event_key: str) -> dict[str, Any]:
    with db.read() as connection:
        row = connection.execute("SELECT * FROM events WHERE id = ?", (event_key,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    event = db.row_to_event(row, include_raw=True)
    event["event_label"] = event_label(row["channel"], row["event_id"], "Windows event")
    return event


@app.get("/api/processes")
def processes(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    with db.read() as connection:
        rows = connection.execute(
            """SELECT process_name, process_path, hostname, pid,
                      MAX(parent_process_name) AS parent_process_name,
                      MAX(parent_pid) AS parent_pid, COUNT(*) AS events,
                      MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
               FROM events WHERE process_name IS NOT NULL
               GROUP BY process_name, process_path, hostname, pid
               ORDER BY events DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/process-lineage")
def process_lineage(limit: int = Query(default=400, ge=1, le=2000),
                    since_hours: int = Query(default=168, ge=1, le=720)) -> dict[str, Any]:
    """Real process parent-child lineage from the process-creation events we actually store.

    Griffendo records two sources of process creation, and they carry different evidence:

      * Sysmon Event ID 1  -> ProcessGuid + ParentProcessGuid: an exact parent identity, which
        is what makes a tree trustworthy.  Collected only when Sysmon is installed.
      * Security 4688      -> NewProcessId + ProcessId: PIDs only, and a PID can be reused, so a
        PID-based link is a *probable* relationship, never an exact one.

    The response therefore separates `exact` (Sysmon GUID) from `probable` (4688 PID) edges and
    states which source each edge came from.  Anything the telemetry cannot prove is left out
    rather than guessed — the UI must not draw a lineage the logs do not support.
    """
    import json
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    with db.read() as connection:
        rows = connection.execute(
            """SELECT hostname, event_time, normalized_json FROM events
               WHERE event_time >= ?
                 AND ((channel = 'Security' AND event_id = 4688)
                      OR (channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1))
               ORDER BY event_time ASC""", (since,)).fetchall()
    for row in rows:
        try:
            fields = (json.loads(row["normalized_json"]) or {}).get("fields") or {}
        except (TypeError, ValueError):
            continue
        sysmon = "ProcessGuid" in fields
        child_name = _basename(fields.get("Image") or fields.get("NewProcessName"))
        parent_name = _basename(fields.get("ParentImage"))
        if not child_name:
            continue
        child_id = fields.get("ProcessGuid") or f"pid:{fields.get('NewProcessId') or fields.get('ProcessId')}"
        parent_id = fields.get("ParentProcessGuid") or (
            f"pid:{fields.get('ProcessId')}" if fields.get("ProcessId") else None)
        child = nodes.setdefault(child_id, {"id": child_id, "name": child_name,
                                            "path": fields.get("Image") or fields.get("NewProcessName"),
                                            "command_line": fields.get("CommandLine"),
                                            "user": fields.get("User") or fields.get("SubjectUserName"),
                                            "host": row["hostname"], "first_seen": row["event_time"],
                                            "source": "sysmon" if sysmon else "security-4688",
                                            "executions": 0, "parent": None})
        child["executions"] += 1
        child["last_seen"] = row["event_time"]
        if parent_name or parent_id:
            if not child["parent"]:
                child["parent"] = {"id": parent_id, "name": parent_name or "unknown",
                                   "exact": bool(fields.get("ParentProcessGuid")),
                                   "source": "sysmon" if sysmon else "security-4688"}
            edges.append({"child": child_id, "parent": parent_id, "parent_name": parent_name,
                          "exact": bool(fields.get("ParentProcessGuid")),
                          "source": "sysmon" if sysmon else "security-4688", "at": row["event_time"]})
    interesting = sorted(nodes.values(),
                         key=lambda n: (0 if n.get("parent") else 1, -n["executions"], n["name"]))[:limit]
    keep = {node["id"] for node in interesting}
    return {"nodes": interesting,
            "edges": [edge for edge in edges if edge["child"] in keep],
            "totals": {"processes": len(nodes), "exact_edges": sum(1 for e in edges if e["exact"]),
                       "probable_edges": sum(1 for e in edges if not e["exact"]),
                       "sources": sorted({node["source"] for node in nodes.values()})},
            "note": ("Exact parent links come from Sysmon process GUIDs. Security 4688 links parent by "
                     "PID only, so a reused PID can make them probable rather than certain.")}


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rstrip("\\").split("\\")[-1] or None


@app.get("/api/timeline")
def timeline(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    with db.read() as connection:
        rows = connection.execute(
            """SELECT id, timestamp, hostname, channel, event_id, provider, process_name, username
               FROM events ORDER BY timestamp DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["label"] = event_label(item["channel"], item["event_id"], item["provider"] or "Windows event")
        result.append(item)
    return result


@app.get("/api/hosts")
def hosts() -> list[dict[str, Any]]:
    with db.read() as connection:
        rows = connection.execute(
            """SELECT a.agent_id, a.hostname, a.os_name, a.last_seen, IFNULL(SUM(h.n), 0) AS events
               FROM agents a LEFT JOIN agg_host h ON h.agent_id = a.agent_id
               GROUP BY a.agent_id ORDER BY a.last_seen DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------- anomaly detection
class ChannelReport(BaseModel):
    channel: str = Field(min_length=1, max_length=255)
    state: str = Field(pattern=r"^(ok|empty|unavailable|access_denied|error)$")
    detail: str | None = Field(default=None, max_length=2000)
    watermark: int | None = Field(default=None, ge=0)
    collected: int | None = Field(default=None, ge=0)
    lookback_hours: int | None = Field(default=None, ge=0)
    last_success_at: str | None = Field(default=None, max_length=40)
    last_error_at: str | None = Field(default=None, max_length=40)
    last_error: str | None = Field(default=None, max_length=2000)
    backfill: str | None = Field(default=None, pattern=r"^(pending|running|complete|not_needed)$")
    backfill_reached: str | None = Field(default=None, max_length=40)
    live_cursor: int | None = Field(default=None, ge=0)
    records_lost: int | None = Field(default=None, ge=0)
    lost_detail: str | None = Field(default=None, max_length=2000)
    log: dict[str, Any] | None = None
    latency: dict[str, Any] | None = None


class CollectorStatus(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    channels: list[ChannelReport] = Field(default_factory=list, max_length=200)
    backend: str | None = Field(default=None, max_length=40)
    version: str | None = Field(default=None, max_length=40)
    mode: str | None = Field(default=None, pattern=r"^(continuous|snapshot)$")
    started_at: str | None = Field(default=None, max_length=40)
    interval_seconds: float | None = Field(default=None, ge=0)
    spool_size: int | None = Field(default=None, ge=0)
    last_delivery_at: str | None = Field(default=None, max_length=40)
    last_error: str | None = Field(default=None, max_length=2000)
    last_error_at: str | None = Field(default=None, max_length=40)
    stats: dict[str, Any] | None = None


class StatusChange(BaseModel):
    status: str
    note: str | None = Field(default=None, max_length=2000)


class RuleToggle(BaseModel):
    enabled: bool


def same_origin_only(request: Request) -> None:
    """Dashboard writes must come from the dashboard itself, not another site in the browser."""
    origin = request.headers.get("origin")
    if origin and origin.split("://", 1)[-1].rstrip("/") != request.headers.get("host", ""):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")


def rule_error(error: anomalies.RuleError) -> JSONResponse:
    return JSONResponse(status_code=error.status,
                        content={"detail": str(error), "errors": error.errors, **error.extra})


@app.post("/api/collector/status", status_code=202, dependencies=[Depends(require_agent_token)])
def collector_status(report: CollectorStatus) -> dict[str, int]:
    return {"recorded": anomalies.record_collector_status(report.model_dump())}


@app.get("/api/collector/config", dependencies=[Depends(require_agent_token)])
def collector_config() -> dict[str, Any]:
    """What a continuous collector should read; polled by the agent so rule changes reach it without a restart."""
    return {"channels": anomalies.collector_channels(), "max_ingest_events": MAX_INGEST_EVENTS,
            "max_ingest_bytes": MAX_INGEST_BYTES, "server_version": APP_VERSION, "store_id": db.store_id()}


@app.get("/api/collector/health")
def collector_health() -> dict[str, Any]:
    health = anomalies.collector_health()
    health["diagnostics"] = db.diagnostics(20)
    return health


@app.get("/api/live")
def live() -> dict[str, Any]:
    """Cheap change marker the UI polls every few seconds; it refreshes only when something changed."""
    with db.read() as connection:
        events_seq = connection.execute("SELECT MAX(rowid) FROM events").fetchone()[0] or 0
        detections_seq = connection.execute("SELECT MAX(updated_at) FROM det_detections").fetchone()[0] or ""
        last_received = connection.execute("SELECT (SELECT received_at FROM events WHERE rowid = (SELECT MAX(rowid) FROM events))").fetchone()[0]
        newest = connection.execute("SELECT MAX(event_time) FROM events").fetchone()[0]
        heartbeat = connection.execute("SELECT MAX(last_heartbeat) FROM collector_agents").fetchone()[0]
    engine = detection_service.service_if_ready()   # never wait for the engine on the 3-second poll
    running = engine.running_jobs() if engine else []
    return {"events_seq": events_seq, "detections_seq": detections_seq, "last_received_at": last_received,
            "newest_event_time": newest, "last_collector_heartbeat": heartbeat,
            "refresh_seconds": settings.ui_refresh_seconds(),
            "anomaly_refresh_seconds": settings.anomaly_refresh_seconds(),
            "server_time": settings.iso(settings.utc_now()),
            "rules_version": engine.registry.version if engine else None,
            "evaluations_running": [{key: job[key] for key in ("rule_id", "examined", "signals")} for job in running],
            "detection_backlog": engine.backlog() if engine else None,
            "engine_ready": bool(engine) and busy.STARTUP["detection_ready"],
            "engine_replaying": bool(engine and engine.replaying),
            "engine_phase": busy.STARTUP["phase"]}


@app.get("/api/config")
def ui_config() -> dict[str, Any]:
    return {"version": APP_VERSION, "refresh_seconds": settings.ui_refresh_seconds(),
            "anomaly_refresh_seconds": settings.anomaly_refresh_seconds(),
            "manual_collection": _COLLECT_TRIGGER is not None,
            "window_days": detection_service.window_days(), "retention_days": settings.retention_days(),
            "storage": "disk" if db.database_path() else "memory", "max_ingest_events": MAX_INGEST_EVENTS}


@app.get("/api/timeline/page")
def timeline_page(
    cursor: str | None = Query(default=None, max_length=400),
    newer_than: str | None = Query(default=None, max_length=400),
    since: str | None = Query(default=None, max_length=40),
    until: str | None = Query(default=None, max_length=40),
    channel: str | None = Query(default=None, max_length=255),
    provider: str | None = Query(default=None, max_length=255),
    host: str | None = Query(default=None, max_length=255),
    event_id: int | None = Query(default=None, ge=0, le=65535),
    level: str | None = Query(default=None, max_length=100),
    anomaly_severity: str | None = Query(default=None, max_length=200),
    anomalies_only: bool = False,
    q: str | None = Query(default=None, max_length=200),
    order: str = Query(default="desc", pattern=r"^(asc|desc)$"),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    params = {"cursor": cursor, "newer_than": newer_than, "since": since, "until": until, "channel": channel,
              "provider": provider, "host": host, "event_id": event_id, "level": level,
              "anomaly_severity": anomaly_severity, "anomalies_only": anomalies_only, "q": q, "order": order}
    try:
        return timeline_queries.page(params, limit)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Invalid cursor: {error}") from error


@app.get("/api/timeline/anomalies")
def timeline_anomalies(
    after: str | None = Query(default=None, max_length=600),
    before: str | None = Query(default=None, max_length=600),
    position: str = Query(default="start", pattern=r"^(start|end)$"),
    changed_since: int | None = Query(default=None, ge=0),
    since: str | None = Query(default=None, max_length=40),
    until: str | None = Query(default=None, max_length=40),
    severity: str | None = Query(default=None, max_length=200),
    channel: str | None = Query(default=None, max_length=255),
    host: str | None = Query(default=None, max_length=255),
    event_id: int | None = Query(default=None, ge=0, le=65535),
    rule_id: str | None = Query(default=None, max_length=100),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    """Active anomalies in the analysis window, oldest first, one entry per event (v4 Timeline)."""
    params = {"after": after, "before": before, "position": position, "changed_since": changed_since,
              "since": since, "until": until, "severity": severity, "channel": channel, "host": host,
              "event_id": event_id, "rule_id": rule_id, "q": q}
    try:
        return timeline_queries.anomaly_page(params, limit)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Invalid cursor: {error}") from error


# --------------------------------------------------------------------------- manual refresh (v4)
# The launcher registers the in-process collector here.  A manual Refresh asks it for an immediate pass,
# waits for that pass, then reports what really happened (never a success that did not occur).
_COLLECT_TRIGGER = None
_REFRESH_LOCK = threading.Lock()


def set_collect_trigger(trigger) -> None:
    global _COLLECT_TRIGGER
    _COLLECT_TRIGGER = trigger


def _markers() -> tuple[int, int]:
    with db.read() as connection:
        return (connection.execute("SELECT MAX(rowid) FROM events").fetchone()[0] or 0,
                connection.execute("SELECT MAX(rowid) FROM det_detections").fetchone()[0] or 0)


@app.post("/api/refresh", dependencies=[Depends(same_origin_only)])
def manual_refresh() -> dict[str, Any]:
    if not _REFRESH_LOCK.acquire(timeout=settings.refresh_collect_timeout() + 15):
        raise HTTPException(status_code=409, detail="Another refresh is still running; try again in a moment.")
    started = time.monotonic()
    try:
        events_before, detections_before = _markers()
        trigger = _COLLECT_TRIGGER
        if trigger is None:
            collection = {"state": "unavailable",
                          "message": ("No collector runs inside this Griffendo window (collection needs Windows and is "
                                      "off with --no-collect or in snapshot mode). Stored data was reloaded; no new "
                                      "events were collected.")}
        else:
            try:
                result = trigger(settings.refresh_collect_timeout())
            except Exception as error:   # never report success for a pass that failed
                result = {"state": "error", "detail": f"{type(error).__name__}: {error}"}
            if result is None:
                collection = {"state": "unavailable", "message": "The collector is not running (yet). Stored data was reloaded."}
            elif result.get("state") == "timeout":
                collection = {"state": "timeout", "message": result.get("detail")}
            elif result.get("state") == "error":
                collection = {"state": "failed", "message": f"Collection failed: {result.get('detail')}"}
            else:
                read, failed = result.get("channels_read") or [], result.get("channels_failed") or []
                missing = result.get("channels_missing") or []
                errors = result.get("errors") or []
                problems = [item for item in errors if not any(str(item).startswith(f"{name}:") for name in missing)]
                delivery_failed = any(str(item).startswith("delivery:") for item in errors)
                absent = f" {len(missing)} log(s) not present on this computer: {', '.join(missing)}." if missing else ""
                if delivery_failed or not read:
                    state = "failed"
                    message = ("Collection failed: " + "; ".join((problems or errors)[:5])) if errors else "Collection failed."
                elif failed:
                    state = "partial"
                    message = (f"Collected from {len(read)} channel(s); {len(failed)} could not be read: "
                               + "; ".join(problems[:5]) + "." + absent)
                else:
                    state = "ok"
                    message = f"Collected from {len(read)} channel(s).{absent}"
                collection = {"state": state, "message": message, "channels_read": read, "channels_failed": failed,
                              "channels_missing": missing,
                              "errors": errors[:20], "read": (result.get("live") or 0) + (result.get("backfill") or 0),
                              "delivered": result.get("delivered") or 0, "spooled": result.get("spool") or 0,
                              "backend": result.get("backend")}
        # Let the detection engine catch up with what was just collected (bounded wait; it keeps running after).
        engine = detection_service.service()
        engine.notify()
        deadline = time.monotonic() + 10
        with busy.waiting_for_engine():
            while engine.backlog() and time.monotonic() < deadline:
                time.sleep(0.1)
        anomalies.invalidate_cache()   # the dashboard re-reads every aggregate after a manual refresh
        detection_queries.invalidate()
        events_after, detections_after = _markers()
        with db.read() as connection:
            new_events = connection.execute("SELECT COUNT(*) FROM events WHERE rowid > ?", (events_before,)).fetchone()[0]
            new_detections = connection.execute("SELECT COUNT(*) FROM det_detections WHERE rowid > ?",
                                                (detections_before,)).fetchone()[0]
        collection["detection_backlog"] = engine.backlog()
        return {"ok": collection["state"] in ("ok", "partial"), "collection": collection,
                "new_events": new_events, "new_detections": new_detections,
                "events_seq": events_after, "detections_seq": detections_after,
                "refreshed_at": settings.iso(settings.utc_now()), "seconds": round(time.monotonic() - started, 3)}
    finally:
        _REFRESH_LOCK.release()


@app.get("/api/timeline/facets")
def timeline_facets() -> dict[str, Any]:
    def produce():
        with db.read() as connection:
            channels = [row[0] for row in connection.execute("SELECT DISTINCT channel FROM events ORDER BY channel")]
            providers = [row[0] for row in connection.execute(
                "SELECT DISTINCT provider FROM events WHERE provider IS NOT NULL ORDER BY provider LIMIT 300")]
            hosts = [row[0] for row in connection.execute("SELECT DISTINCT hostname FROM events ORDER BY hostname")]
        return {"channels": channels, "providers": providers, "hosts": hosts, "levels": list(timeline_queries.LEVELS)}
    return anomalies._cached("timeline-facets", produce, ttl=30)


# --------------------------------------------------------------------------- legacy v2-v4 anomaly history
# The v4 Event-ID engine no longer runs (the detection engine replaced it, and its catalog rules live on as
# detection rules).  Detections it stored stay readable here, unchanged, as history.
@app.get("/api/anomalies/summary")
def anomaly_summary() -> dict[str, Any]:
    result = anomalies.summary()
    result["legacy"] = True
    return result


@app.get("/api/anomalies/coverage")
def anomaly_coverage() -> dict[str, Any]:
    coverage = anomalies.coverage_overview()
    coverage["channels"] = anomalies.channel_status()
    return coverage


@app.get("/api/anomalies")
def anomaly_list(
    severity: str | None = Query(default=None, max_length=200),
    event_id: int | None = None,
    category: str | None = Query(default=None, max_length=100),
    channel: str | None = Query(default=None, max_length=255),
    host: str | None = Query(default=None, max_length=255),
    status: str | None = Query(default=None, max_length=40),
    rule_id: str | None = Query(default=None, max_length=100),
    since: str | None = Query(default=None, max_length=40),
    until: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    params = {"severity": severity, "event_id": event_id, "category": category, "channel": channel,
              "host": host, "status": status, "rule_id": rule_id, "since": since, "until": until, "q": q}
    result = anomalies.list_anomalies(params, limit, offset, scope="all")
    result["legacy"] = True
    return result


@app.get("/api/anomalies/{detection_id}")
def anomaly_detail(detection_id: str) -> dict[str, Any]:
    item = anomalies.get_anomaly(detection_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return item


@app.post("/api/anomalies/{detection_id}/status", dependencies=[Depends(same_origin_only)])
def anomaly_status(detection_id: str, change: StatusChange = Body(...)) -> dict[str, Any]:
    try:
        item = anomalies.set_status(detection_id, change.status, (change.note or "").strip() or None)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if item is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return item


# --------------------------------------------------------------------------- rule management (v5 engine)
@app.get("/api/rules")
def rules_list() -> dict[str, Any]:
    return detection_queries.rules({"limit": 2000})


def main() -> None:
    import uvicorn

    uvicorn.run(
        "logplatform.app:app",
        host=os.getenv("LOGPLATFORM_HOST", "127.0.0.1"),
        port=int(os.getenv("LOGPLATFORM_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
