"""HTTP API of the Detection and Correlation Engine (v5).

Every number shown by the Detections page, the Overview's detection columns, the Endpoint
page and the timeline comes from detection/engine/queries.py through these routes.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from . import anomalies, db, settings
from .detection.engine import conditions, feedback, queries, registry as reg, risk, schema
from .detection.engine.service import service

def _engine_ready() -> None:
    """Detection pages answer at once while the engine is still starting, instead of hanging.

    The rules load in the background after the server starts (a few seconds; longer on a slow disk).
    A short 503 tells the page to show a notice; the page reloads by itself when the engine is ready.
    """
    from .detection.engine.service import service_if_ready
    deadline = time.monotonic() + 2.0
    while service_if_ready() is None:
        if time.monotonic() >= deadline:
            from . import busy
            raise HTTPException(status_code=503, detail="The detection engine is still starting "
                                f"({busy.STARTUP['phase']}). This page fills in by itself when it is ready.")
        time.sleep(0.05)


router = APIRouter(dependencies=[Depends(_engine_ready)])
PRESETS = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "6h": timedelta(hours=6),
           "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{2,63}$")
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")


def same_origin_only(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin.split("://", 1)[-1].rstrip("/") != request.headers.get("host", ""):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")


def time_range(range_: str | None, start: str | None, end: str | None, default: str | None = "7d") \
        -> tuple[str | None, str | None, str]:
    """(start, end, label) in fixed-width UTC text; raises 422 on bad input or start after end."""
    now = settings.utc_now()
    if start or end:
        parsed_start = settings.parse_time(start) if start else None
        parsed_end = settings.parse_time(end) if end else None
        if start and parsed_start is None:
            raise HTTPException(status_code=422, detail=f"Start time {start!r} is not a valid ISO-8601 time.")
        if end and parsed_end is None:
            raise HTTPException(status_code=422, detail=f"End time {end!r} is not a valid ISO-8601 time.")
        if parsed_start and parsed_end and parsed_start > parsed_end:
            raise HTTPException(status_code=422, detail="The start time is later than the end time.")
        return (settings.iso(parsed_start) if parsed_start else None,
                settings.iso(parsed_end) if parsed_end else None, "custom")
    key = range_ or default
    if key is None or key == "all":
        return None, None, "all"
    if key not in PRESETS:
        raise HTTPException(status_code=422, detail=f"Unknown range {key!r}; use one of {', '.join(PRESETS)} or start/end.")
    return settings.iso(now - PRESETS[key]), settings.iso(now + timedelta(minutes=5)), key


# --------------------------------------------------------------------------- detections
@router.get("/api/detections")
def detections(
    range: str | None = Query(default=None, max_length=10),
    start: str | None = Query(default=None, max_length=40),
    end: str | None = Query(default=None, max_length=40),
    severity: str | None = Query(default=None, max_length=200),
    category: str | None = Query(default=None, max_length=100),
    rule_id: str | None = Query(default=None, max_length=100),
    rule: str | None = Query(default=None, max_length=200),
    event_id: int | None = Query(default=None, ge=0, le=65535),
    status: str | None = Query(default=None, max_length=40),
    verdict: str | None = Query(default=None, max_length=40),
    rule_state: str | None = Query(default=None, pattern=r"^(enabled|disabled)$"),
    source: str | None = Query(default=None, pattern=r"^(rule|chain|behavior)$"),
    host: str | None = Query(default=None, max_length=255),
    q: str | None = Query(default=None, max_length=200),
    scope: str = Query(default="active", pattern=r"^(active|suppressed|inactive|all)$"),
    sort: str = Query(default="time_desc", pattern=r"^(time_desc|time_asc|score_desc|severity)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    begin, finish, label = time_range(range, start, end)
    params = {"start": begin, "end": finish, "severity": [s.strip() for s in (severity or "").split(",") if s.strip()],
              "category": category, "rule_id": rule_id, "rule": rule, "event_id": event_id, "status": status,
              "verdict": verdict, "rule_state": rule_state, "source": source, "host": host, "q": q, "scope": scope,
              "sort": sort}
    result = queries.list_detections(params, limit, offset)
    result["range"] = {"start": begin, "end": finish, "label": label}
    return result


@router.get("/api/detections/summary")
def detections_summary(range: str | None = Query(default=None, max_length=10),
                       start: str | None = Query(default=None, max_length=40),
                       end: str | None = Query(default=None, max_length=40),
                       recent: int = Query(default=5, ge=1, le=20)) -> dict[str, Any]:
    begin, finish, label = time_range(range, start, end)
    result = queries.summary(begin, finish, recent)
    result["range"]["label"] = label
    return result


@router.get("/api/detections/status")
def detections_status() -> dict[str, Any]:
    start, end = queries.default_range()
    return {"processing": queries.processing_status(), "summary_counts": queries.severity_counts(start, end),
            "model": service().behavior.status()}


@router.get("/api/detections/schema")
def detection_schema() -> dict[str, Any]:
    """What the rule builder offers: normalized fields, operators, sources and severities."""
    sources = []
    for key, source in schema.SOURCES.items():
        sources.append({"key": key, "channel": source["channel"], "event_ids": source["event_ids"],
                        "fields": sorted(schema.fields_for(key) - schema.COMMON_FIELDS)})
    return {"fields": [{"field": k, "label": v} for k, v in schema.BUILDER_FIELDS.items()],
            "raw_prefix": schema.RAW_PREFIX, "operators": sorted(conditions.OPS - {"eq_field", "ne_field"}),
            "functions": sorted(conditions.FNS), "severities": list(risk.SEVERITIES),
            "kinds": ["single", "threshold", "sequence"], "sources": sources,
            "channels": sorted({s["channel"] for s in schema.SOURCES.values()} |
                               {schema.SECURITY, schema.SYSTEM, schema.APPLICATION, schema.DEFENDER, schema.FIREWALL,
                                schema.TASKS, schema.WMI}),
            "severity_bands": dict(zip(("critical", "high", "medium", "low"), risk.thresholds()))}


@router.get("/api/detections/model")
def model_status() -> dict[str, Any]:
    svc = service()
    with db.read() as connection:
        shadow = connection.execute(
            "SELECT id, rule_id, rule_name, first_time, score, decision, details_json FROM det_signals "
            "WHERE source = 'behavior' AND decision IN ('shadow', 'learn_only') ORDER BY first_time DESC LIMIT 25").fetchall()
    return {**svc.behavior.status(), "audit": svc.models.audit_log(30),
            "shadow_signals": [{k: row[k] for k in ("id", "rule_id", "rule_name", "first_time", "score", "decision")}
                               for row in shadow]}


@router.post("/api/detections/model/reset", dependencies=[Depends(same_origin_only)])
def model_reset() -> dict[str, Any]:
    return service().reset_model()


@router.delete("/api/suppressions/{suppression_id}", dependencies=[Depends(same_origin_only)])
def suppression_revoke(suppression_id: str) -> dict[str, Any]:
    if not service().revoke_suppression(suppression_id):
        raise HTTPException(status_code=404, detail="Suppression not found or already revoked")
    return {"revoked": suppression_id}


@router.get("/api/timeline/detections")
def timeline_detections(
    after: str | None = Query(default=None, max_length=300),
    before: str | None = Query(default=None, max_length=300),
    position: str = Query(default="start", pattern=r"^(start|end)$"),
    range: str | None = Query(default=None, max_length=10),
    start: str | None = Query(default=None, max_length=40),
    end: str | None = Query(default=None, max_length=40),
    severity: str | None = Query(default=None, max_length=200),
    rule_id: str | None = Query(default=None, max_length=100),
    event_id: int | None = Query(default=None, ge=0, le=65535),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    begin, finish, label = time_range(range, start, end)
    params = {"after": after, "before": before, "position": position, "start": begin, "end": finish,
              "severity": [s.strip() for s in (severity or "").split(",") if s.strip()], "rule_id": rule_id,
              "event_id": event_id, "q": q}
    try:
        result = queries.timeline_page(params, limit)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Invalid cursor: {error}") from error
    result["range"] = {"start": begin, "end": finish, "label": label}
    return result


# --------------------------------------------------------------------------- endpoint page
@router.get("/api/endpoint")
def endpoint() -> dict[str, Any]:
    """The monitored host: identity, monitoring and collection state, and its detections (shared summary)."""
    svc = service()
    with db.read() as connection:
        agents = [dict(row) for row in connection.execute(
            "SELECT agent_id, hostname, os_name, last_seen FROM agents ORDER BY last_seen DESC")]
        # Hosts that sent events (trigger-maintained aggregate; scanning det_detections took 100+ ms).
        hosts = [row[0] for row in connection.execute("SELECT DISTINCT hostname FROM agg_host WHERE n > 0 LIMIT 20")]
    health = anomalies.collector_health()
    channels = anomalies.channel_status()
    summary = queries.summary(recent=8)
    optional = []
    for name, label in ((schema.SYSMON, "Sysmon"), (schema.DEFENDER, "Windows Defender"),
                        (schema.POWERSHELL, "PowerShell Operational")):
        item = next((c for c in channels if c["channel"].lower() == name.lower()), None)
        optional.append({"source": label, "channel": name, "state": item["state"] if item else "not_configured",
                         "state_label": item["state_label"] if item else "Not collected",
                         "events_stored": item["events_stored"] if item else 0,
                         "rules": svc.registry.channels().get(name, 0)})
    with db.read() as connection:
        counts = connection.execute("SELECT COUNT(*), MAX(det_time) FROM det_detections WHERE active = 1").fetchone()
    return {"hosts": agents, "detection_hosts": hosts, "collector": health,
            "channels": [{k: c[k] for k in ("channel", "state", "state_label", "coverage", "coverage_label",
                                             "events_stored", "last_success_at", "enabled_rules")} for c in channels],
            "optional_sources": optional, "detections": {"active_total": counts[0], "latest": counts[1],
                                                         "counts": summary["counts"], "columns": summary["columns"],
                                                         "range": summary["range"]},
            "model": svc.behavior.status(), "processing": summary["processing"]}


# --------------------------------------------------------------------------- rules
def _rule_error(status: int, message: str, errors: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message, "errors": errors or {}})


@router.get("/api/detections/rules")
def rules(q: str | None = Query(default=None, max_length=200), origin: str | None = Query(default=None, max_length=20),
          kind: str | None = Query(default=None, max_length=20), state: str | None = Query(default=None, max_length=10),
          severity: str | None = Query(default=None, max_length=20), support: str | None = Query(default=None, max_length=40),
          sort: str = Query(default="signals", max_length=20), include_grouping: bool = False,
          limit: int = Query(default=200, ge=1, le=2000), offset: int = Query(default=0, ge=0)) -> dict[str, Any]:
    return queries.rules({"q": q, "origin": origin, "kind": kind, "state": state, "severity": severity,
                          "support": support, "sort": sort, "include_grouping": include_grouping, "limit": limit,
                          "offset": offset})


@router.get("/api/detections/rules/{rule_id}")
def rule_detail(rule_id: str) -> dict[str, Any]:
    item = queries.rule_detail(rule_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return item


@router.put("/api/detections/rules/{rule_id}/enabled", dependencies=[Depends(same_origin_only)])
def rule_enabled(rule_id: str, payload: dict[str, Any] = Body(...)):
    if not isinstance(payload.get("enabled"), bool):
        return _rule_error(422, "'enabled' must be true or false")
    svc = service()
    try:
        result = svc.set_enabled(rule_id, payload["enabled"])
    except KeyError:
        raise HTTPException(status_code=404, detail="Rule not found") from None
    except reg.RuleError as error:
        return _rule_error(409, str(error))
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail=f"Setting could not be saved: {error}") from error
    result["job"] = svc.wait_job(rule_id, 2.0)
    queries.invalidate()
    return result


def _field_ok(sources: list[dict[str, Any]]):
    def check(field: str) -> str | None:
        name = field.removesuffix(".caseless")
        if name.startswith(schema.RAW_PREFIX):
            return None
        known = set(schema.BUILDER_FIELDS) | schema.COMMON_FIELDS | {f for s in schema.SOURCES.values() for f in s["fields"]}
        known |= {f for fields in schema.GENERIC_FIELDS.values() for f in fields}
        if name not in known:
            return (f"Field '{field}' is not collected by Griffendo (it is not in the normalized event schema). "
                    f"Use a listed field or winlog.event_data.<Name> for a raw EventData value.")
        usable = False
        for source in sources:
            ids = source.get("event_ids") or [None]
            for eid in ids:
                key = schema.source_key(source.get("channel"), eid)
                if schema.field_available(name, key, source.get("channel")):
                    usable = True
        if sources and not usable:
            providers = sorted({s["channel"] + " " + ",".join(map(str, s["event_ids"])) for s in schema.SOURCES.values()
                                if name in s["fields"]})
            return (f"Field '{field}' is never present in the selected sources, so the rule could never match. "
                    + (f"It is available from: {'; '.join(providers)}." if providers else ""))
        return None
    return check


def _custom_definition(payload: dict[str, Any], existing: str | None = None) -> dict[str, Any]:
    errors: dict[str, str] = {}

    def text(key: str, required: bool, maximum: int) -> str | None:
        value = payload.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            if required:
                errors[key] = "Required."
            return None
        if not isinstance(value, str) or len(value) > maximum:
            errors[key] = f"Text up to {maximum} characters."
            return None
        return value.strip()

    definition: dict[str, Any] = {
        "name": text("name", True, 200), "description": text("description", True, 4000),
        "category": text("category", True, 100), "explanation": text("explanation", True, 4000),
        "investigation": text("investigation", True, 4000), "author": text("author", False, 200),
        "notes": text("notes", False, 4000),
    }
    severity = payload.get("severity")
    if severity not in risk.SEVERITIES:
        errors["severity"] = f"One of {', '.join(risk.SEVERITIES)}."
    definition["severity"] = severity
    kind = payload.get("kind") or "single"
    if kind not in ("single", "threshold", "sequence"):
        errors["kind"] = "single, threshold or sequence."
    definition["kind"] = kind
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        errors["sources"] = "Choose at least one event channel (and its Event IDs)."
        sources = []
    clean_sources = []
    for source in sources[:20]:
        channel = str((source or {}).get("channel") or "").strip()
        ids = (source or {}).get("event_ids") or []
        if not re.match(r"^[A-Za-z0-9 ._()/\-]{1,255}$", channel):
            errors["sources"] = f"Invalid channel name {channel!r}."
            continue
        try:
            ids = sorted({int(i) for i in ids})
        except (TypeError, ValueError):
            errors["sources"] = "Event IDs must be whole numbers."
            continue
        if any(not 0 <= i <= 65535 for i in ids):
            errors["sources"] = "Event IDs are between 0 and 65535."
        clean_sources.append({"channel": channel, "event_ids": ids})
    definition["sources"] = clean_sources
    field_ok = _field_ok(clean_sources)
    if kind in ("single", "threshold"):
        problems = conditions.validate(payload.get("condition"), field_ok)
        if problems:
            errors["condition"] = " ".join(dict.fromkeys(problems))
        definition["condition"] = payload.get("condition")
    if kind == "threshold":
        threshold = payload.get("threshold") or {}
        try:
            count, window = int(threshold.get("count")), int(threshold.get("window_seconds"))
        except (TypeError, ValueError):
            count, window = 0, 0
        by = [str(f) for f in threshold.get("by") or []][:5]
        if count < 2:
            errors["threshold"] = "The count must be 2 or more (use a single-event rule for 1)."
        if not 1 <= window <= 7 * 86400:
            errors["threshold"] = "The window must be between 1 second and 7 days."
        for name in by:
            problem = field_ok(name)
            if problem:
                errors["threshold"] = problem
        definition["threshold"] = {"by": by, "count": count, "window_seconds": window}
    if kind == "sequence":
        steps = payload.get("steps") or []
        if not isinstance(steps, list) or len(steps) < 2:
            errors["steps"] = "A sequence needs at least two steps."
            steps = []
        clean_steps = []
        for index, step in enumerate(steps[:10]):
            problems = conditions.validate((step or {}).get("condition"), field_ok)
            if problems:
                errors[f"steps.{index}"] = " ".join(dict.fromkeys(problems))
            by = [str(f) for f in (step or {}).get("by") or []][:3]
            for name in by:
                problem = field_ok(name)
                if problem:
                    errors[f"steps.{index}"] = problem
            clean_steps.append({"condition": (step or {}).get("condition"), "by": by,
                                "runs": max(1, min(int((step or {}).get("runs") or 1), 100))})
        definition["steps"] = clean_steps
        try:
            definition["maxspan"] = int(payload.get("maxspan"))
        except (TypeError, ValueError):
            definition["maxspan"] = 0
        if not 1 <= definition["maxspan"] <= 7 * 86400:
            errors["maxspan"] = "Between 1 second and 7 days."
    mitre = []
    for item in payload.get("mitre") or []:
        technique = str((item or {}).get("technique") if isinstance(item, dict) else item).strip().upper()
        if technique and not MITRE.match(technique):
            errors["mitre"] = "Use technique IDs like T1059 or T1059.001."
        elif technique:
            mitre.append({"tactic": "", "technique": technique, "name": ""})
    definition["mitre"] = mitre
    definition["enabled"] = bool(payload.get("enabled", True))
    rule_id = payload.get("rule_id") if existing is None else existing
    if existing is None:
        if rule_id:
            if not RULE_ID.match(str(rule_id)) or str(rule_id).upper().startswith(("ELA-", "WAZ-", "CHN-", "COR-", "BEH-")):
                errors["rule_id"] = "3-64 letters, digits, '.', '_' or '-'; the ELA/WAZ/CHN/COR/BEH prefixes are reserved."
        else:
            slug = re.sub(r"[^A-Za-z0-9]+", "-", definition["name"] or "rule").strip("-")[:30].upper()
            rule_id = f"CUS-{slug}-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:4].upper()}"
    definition["rule_id"] = rule_id
    if errors:
        raise ValueError(errors)
    return definition


@router.post("/api/detections/rules/validate", dependencies=[Depends(same_origin_only)])
def rule_validate(payload: dict[str, Any] = Body(...)):
    try:
        definition = _custom_definition(payload)
    except ValueError as error:
        return _rule_error(422, "The rule is not valid.", error.args[0])
    return {"valid": True, "rule_id": definition["rule_id"]}


@router.post("/api/detections/rules", status_code=201, dependencies=[Depends(same_origin_only)])
def rule_create(payload: dict[str, Any] = Body(...)):
    try:
        definition = _custom_definition(payload)
    except ValueError as error:
        return _rule_error(422, "The rule is not valid.", error.args[0])
    svc = service()
    try:
        result = svc.save_custom(definition)
    except reg.RuleError as error:
        return _rule_error(409, str(error), {"rule_id": str(error)})
    except KeyError:
        return _rule_error(409, "A rule with this id already exists.", {"rule_id": "Already exists."})
    result["job"] = svc.wait_job(definition["rule_id"], 2.0)
    queries.invalidate()
    return result


@router.put("/api/detections/rules/{rule_id}", dependencies=[Depends(same_origin_only)])
def rule_update(rule_id: str, payload: dict[str, Any] = Body(...)):
    svc = service()
    current = svc.registry.get(rule_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if current.origin != "custom":
        return _rule_error(409, "Imported and built-in rules cannot be edited; switch them off and create a custom "
                                "rule instead.")
    try:
        definition = _custom_definition(payload, existing=rule_id)
    except ValueError as error:
        return _rule_error(422, "The rule is not valid.", error.args[0])
    result = svc.save_custom(definition, rule_id=rule_id)
    result["job"] = svc.wait_job(rule_id, 2.0)
    queries.invalidate()
    return result


@router.delete("/api/detections/rules/{rule_id}", dependencies=[Depends(same_origin_only)])
def rule_delete(rule_id: str):
    svc = service()
    current = svc.registry.get(rule_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if current.origin != "custom":
        return _rule_error(409, "Imported and built-in rules cannot be deleted; switch them off instead.")
    result = svc.delete_custom(rule_id)
    result["job"] = svc.wait_job(rule_id, 2.0)
    queries.invalidate()
    return result


# Detail routes last: '/api/detections/{id}' must not shadow '/api/detections/rules'.
@router.get("/api/detections/{detection_id}")
def detection_detail(detection_id: str) -> dict[str, Any]:
    item = queries.get_detection(detection_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return item


@router.post("/api/detections/{detection_id}/status", dependencies=[Depends(same_origin_only)])
def detection_status(detection_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        at = service().set_status(detection_id, str(payload.get("status")), (payload.get("note") or "").strip()[:2000] or None)
    except KeyError:
        raise HTTPException(status_code=404, detail="Detection not found") from None
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    queries.invalidate()
    return {"status": payload.get("status"), "at": at}


@router.post("/api/detections/{detection_id}/verdict", dependencies=[Depends(same_origin_only)])
def detection_verdict(detection_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        result = service().set_verdict(detection_id, str(payload.get("verdict")),
                                       (payload.get("note") or "").strip()[:2000] or None)
    except KeyError:
        raise HTTPException(status_code=404, detail="Detection not found") from None
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    queries.invalidate()
    return result


@router.post("/api/detections/{detection_id}/suppress", dependencies=[Depends(same_origin_only)])
def detection_suppress(detection_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        return service().suppress(detection_id, str(payload.get("reason") or ""))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


_ = (datetime, feedback)
