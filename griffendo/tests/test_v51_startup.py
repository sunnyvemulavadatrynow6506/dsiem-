"""v5.1: the dashboard answers at once while the detection engine starts, and the engine gives way to requests."""
from __future__ import annotations

import threading
import time

from conftest import AUTH, drain


def test_dashboard_answers_while_the_engine_is_still_starting(state_dir, monkeypatch):
    from fastapi.testclient import TestClient
    from logplatform.app import app
    from logplatform.detection.engine import service as svc_module

    release = threading.Event()
    original = svc_module.DetectionService.__init__

    def slow_init(self, *args, **kwargs):
        release.wait(10)                    # stands in for loading 1,456 rules and a long replay
        original(self, *args, **kwargs)

    monkeypatch.setattr(svc_module.DetectionService, "__init__", slow_init)
    with TestClient(app) as client:
        started = time.monotonic()
        health = client.get("/api/health").json()
        live = client.get("/api/live").json()
        overview = client.get("/api/overview")
        assert time.monotonic() - started < 2.0
        assert health["status"] == "ok" and health["detection_ready"] is False
        assert live["engine_ready"] is False and live["detection_backlog"] is None
        assert overview.status_code == 200
        waited = time.monotonic()
        pending = client.get("/api/detections/summary")             # answers with a notice, does not hang
        assert pending.status_code == 503 and "starting" in pending.json()["detail"]
        assert time.monotonic() - waited < 4.0
        release.set()
        for _ in range(200):
            if client.get("/api/health").json()["detection_ready"]:
                break
            time.sleep(0.05)
        assert client.get("/api/health").json()["phase"] == "ready"
        assert client.get("/api/live").json()["engine_ready"] is True


def test_backlog_is_counted_without_scanning(client):
    import synthetic
    from logplatform.detection.engine.service import service

    from v5_events import Builder
    builder = Builder()
    events = [builder.logon(builder.at(i), f"user{i}", hex(0x7000 + i)) for i in range(30)]
    response = client.post("/api/ingest", json=synthetic.batch(events), headers=AUTH)
    assert response.status_code == 202
    assert service().backlog() == 30
    drain()
    assert service().backlog() == 0


def test_identical_condition_tests_are_shared_and_remembered_per_event():
    from logplatform.detection.engine import conditions
    leaf = {"field": "winlog.channel", "op": "eq", "values": ["Security"], "ci": True}
    a = conditions.compile_condition({"all": [leaf, {"field": "event.code", "op": "eq", "values": ["4624"]}]})
    b = conditions.compile_condition({"all": [dict(leaf), {"field": "event.code", "op": "eq", "values": ["4625"]}]})
    assert conditions.compile_condition(leaf) is conditions.compile_condition(dict(leaf))
    event = {"winlog.channel": "Security", "event.code": "4624", "_lower": {}, "_m": {}}
    assert a(event) and not b(event)
    assert event["_m"]                                   # results remembered for this event only
    other = {"winlog.channel": "System", "event.code": "4624", "_lower": {}, "_m": {}}
    assert not a(other)
    plain = {"winlog.channel": "Security", "event.code": "4625", "_lower": {}}   # no memo: evaluated directly
    assert b(plain) and not a(plain)


def test_waiting_for_the_engine_outside_a_request_changes_nothing():
    from logplatform import busy
    before = busy._IN_FLIGHT
    with busy.waiting_for_engine():
        pass
    assert busy._IN_FLIGHT == before
    busy.enter()
    try:
        with busy.waiting_for_engine():
            assert busy._IN_FLIGHT == before
        assert busy._IN_FLIGHT == before + 1
    finally:
        busy.leave()
