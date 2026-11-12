"""v3 timeline paging, continuous collection, parsing and coverage. All data is synthetic."""
from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import synthetic
from conftest import AUTH, ingest
from fakelog import FakeLog

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731
BASE = ("System", "Security", "Setup", "Application")


def walk(client, **params):
    seen, cursor, pages, last = [], None, 0, None
    while True:
        query = dict(params, limit=params.get("limit", 500))
        if cursor:
            query["cursor"] = cursor
        page = client.get("/api/timeline/page", params=query).json()
        pages += 1
        seen.extend(page["items"])
        cursor = page["next_cursor"]
        last = page
        if not cursor:
            return seen, pages, last


# ----------------------------------------------------------------- timeline
def test_timeline_covers_entire_window_without_gaps_or_duplicates(client):
    now = NOW()
    inside = [synthetic.envelope(4624 if i % 7 else 4625, "Security", now - timedelta(seconds=i * 113), i + 1)
              for i in range(5200)]                    # ~6.8 days, more than two old 2,000-event batches
    outside = [synthetic.envelope(4624, "Security", now - timedelta(days=8, minutes=i), 90000 + i) for i in range(30)]
    for start in range(0, len(inside), 5000):         # one request carries 5,000 events (old limit: 2,000)
        ingest(client, inside[start:start + 5000])
    ingest(client, outside)
    items, pages, last = walk(client)
    assert len(items) == 5200 and len({i["id"] for i in items}) == 5200 and pages == 11
    assert last["total"] == 5200
    times = [i["event_time"] for i in items]
    assert times == sorted(times, reverse=True)
    items_asc, _, _ = walk(client, order="asc")
    assert [i["id"] for i in items_asc] == [i["id"] for i in reversed(items)]
    flagged, _, _ = walk(client, anomalies_only="true")
    assert len(flagged) == sum(1 for i in range(5200) if i % 7 == 0) and all(i["anomaly"] for i in flagged)
    by_id, _, page = walk(client, event_id=4625)
    assert page["total"] == len(by_id) == len(flagged)


def test_paging_is_stable_while_events_arrive(client):
    now = NOW()
    ingest(client, [synthetic.envelope(4624, "Security", now - timedelta(minutes=i), i + 1) for i in range(1000)])
    first = client.get("/api/timeline/page", params={"limit": 300}).json()
    # New events arrive (newer and older than the page boundary) while the user is paging.
    ingest(client, [synthetic.envelope(4688, "Security", now + timedelta(seconds=1 + i), 5000 + i) for i in range(50)])
    ingest(client, [synthetic.envelope(4688, "Security", now - timedelta(minutes=500, seconds=30 + i), 6000 + i) for i in range(5)])
    rest, cursor = [], first["next_cursor"]
    while cursor:
        page = client.get("/api/timeline/page", params={"limit": 300, "cursor": cursor}).json()
        rest.extend(page["items"])
        cursor = page["next_cursor"]
    ids = [i["id"] for i in first["items"]] + [i["id"] for i in rest]
    assert len(ids) == len(set(ids)) == 1005           # original 1000 + 5 older ones; nothing skipped or repeated
    newer = client.get("/api/timeline/page", params={"newer_than": first["top_cursor"], "limit": 500}).json()
    assert len(newer["items"]) == 50 and not set(i["id"] for i in newer["items"]) & set(ids)


def test_timeline_filters_and_bad_cursor(client):
    ingest(client, synthetic.demo_dataset())
    assert client.get("/api/timeline/page", params={"cursor": "not-a-cursor"}).status_code == 422
    page = client.get("/api/timeline/page", params={"channel": "System", "limit": 500}).json()
    assert page["items"] and {i["channel"] for i in page["items"]} == {"System"}
    page = client.get("/api/timeline/page", params={"q": "SYNTHETIC-WS01", "limit": 5}).json()
    assert page["total"] == len([e for e in synthetic.demo_dataset()]) - 1     # the 9-day-old event is outside
    page = client.get("/api/timeline/page", params={"anomaly_severity": "Critical"}).json()
    assert page["items"] and all(i["anomaly"]["severity"] == "Critical" for i in page["items"])
    legacy = client.get("/api/timeline", params={"limit": 3}).json()            # v1 endpoint unchanged
    assert isinstance(legacy, list) and len(legacy) == 3


def test_large_batches_are_accepted(client):
    events = [synthetic.envelope(4624, "Security", NOW() - timedelta(seconds=i), i + 1) for i in range(8000)]
    assert ingest(client, events) == {"accepted": 8000, "inserted": 8000}


# ----------------------------------------------------------------- parsing
FIXTURES = {
    "security_4624": ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-10-26T05:12:44.1234567Z"/><EventRecordID>184467</EventRecordID><Correlation ActivityID="{a}"/><Execution ProcessID="788" ThreadID="812"/><Channel>Security</Channel><Computer>SYNTHETIC-WS01.lab.local</Computer><Security/></System><EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="TargetUserName">demo</Data><Data Name="TargetDomainName">LAB</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">198.51.100.23</Data><Data Name="ProcessName">-</Data></EventData></Event>', 4624),
    "system_7036_qualifiers": ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager" EventSourceName="Service Control Manager"/><EventID Qualifiers="16384">7036</EventID><Level>4</Level><TimeCreated SystemTime="2026-10-26T05:12:44.000000000Z"/><EventRecordID>9</EventRecordID><Channel>System</Channel><Computer>SYNTHETIC-WS01</Computer></System><EventData><Data Name="param1">Windows Update</Data><Data Name="param2">running</Data><Binary>770075006100750073007600</Binary></EventData></Event>', 7036),
    "eventlog_1102_userdata": ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><Level>4</Level><TimeCreated SystemTime="2026-10-26T05:12:44Z"/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>SYNTHETIC-WS01</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>synthetic.admin</SubjectUserName><Nested><Deeper>kept</Deeper></Nested></LogFileCleared></UserData></Event>', 1102),
    "defender_spaces": ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Windows Defender"/><EventID>1116</EventID><Level>3</Level><TimeCreated SystemTime="2026-10-26T10:42:44.5+05:30"/><EventRecordID>77</EventRecordID><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>SYNTHETIC-WS01</Computer></System><EventData><Data Name="Threat Name">Synthetic:Test/EICAR</Data><Data Name="Path">file:_C:\\x.com</Data></EventData></Event>', 1116),
    "unnamed_data": ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Legacy"/><EventID>65535</EventID><TimeCreated SystemTime="2026-10-26T05:12:44Z"/><EventRecordID>5</EventRecordID></System><EventData><Data>first</Data><Data>second</Data></EventData></Event>', 65535),
}


def test_representative_event_xml_parses_correctly():
    from logplatform.parser import parse_event
    from logplatform.settings import normalize_time

    parsed = {name: parse_event(xml) for name, (xml, _) in FIXTURES.items()}
    for name, (_, event_id) in FIXTURES.items():
        assert parsed[name]["event_id"] == event_id and isinstance(parsed[name]["event_id"], int), name
        assert "parse_error" not in parsed[name], name
    sec = parsed["security_4624"]
    assert (sec["record_id"], sec["channel"], sec["computer"]) == (184467, "Security", "SYNTHETIC-WS01.lab.local")
    assert sec["fields"]["LogonType"] == "10" and sec["user"] == "demo"
    assert normalize_time(sec["timestamp"]) == "2026-10-26T05:12:44.123456Z"
    assert parsed["system_7036_qualifiers"]["fields"] == {"param1": "Windows Update", "param2": "running"}
    assert parsed["eventlog_1102_userdata"]["fields"]["SubjectUserName"] == "synthetic.admin"
    assert parsed["eventlog_1102_userdata"]["fields"]["Deeper"] == "kept"          # nested UserData no longer dropped
    assert parsed["defender_spaces"]["fields"]["Threat Name"] == "Synthetic:Test/EICAR"
    assert normalize_time(parsed["defender_spaces"]["timestamp"]) == "2026-10-26T05:12:44.500000Z"   # offset -> UTC
    assert parsed["unnamed_data"]["fields"] == {"field_0": "first", "field_1": "second"}


def test_malformed_and_incomplete_events_are_diagnosed_not_dropped(client):
    good = synthetic.envelope(4720, "Security", NOW(), 1)
    broken = {"id": "b" * 64, "channel": "Security", "record_id": 2, "xml": "<Event><System><EventID>4720"}
    no_time = synthetic.envelope(4726, "Security", None, 3)
    no_id = {"id": "c" * 64, "channel": "Security", "record_id": 4,
             "xml": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="x"/></System></Event>'}
    assert ingest(client, [good, broken, no_time, no_id]) == {"accepted": 4, "inserted": 4}
    problems = client.get("/api/collector/health").json()["diagnostics"]["items"]
    kinds = " | ".join(p["problem"] for p in problems)
    assert "Invalid Windows Event XML" in kinds and "No numeric EventID" in kinds and "TimeCreated" in kinds
    assert not any("4720" in (p.get("sample") or "") for p in problems)           # no event content in diagnostics
    flagged_ids = {i["event_id"] for i in client.get("/api/timeline/page", params={"anomalies_only": "true"}).json()["items"]}
    assert flagged_ids == {4720, 4726}                      # events with missing fields/time are still detected


# ----------------------------------------------------------------- continuous collection (real HTTP receiver)
@pytest.fixture
def receiver(state_dir, monkeypatch):
    import uvicorn
    from logplatform.app import app

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    monkeypatch.setenv("LOGPLATFORM_URL", f"http://127.0.0.1:{port}/api/ingest")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)
    base = f"http://127.0.0.1:{port}"
    yield base
    server.should_exit = True
    thread.join(timeout=10)


def make_log(**extra):
    log = FakeLog()
    for channel in (*BASE, *extra.get("channels", ())):
        log.logs.setdefault(channel, [])
    return log


def collector(log, state_dir, clock=None, session=None):
    from agent.continuous import ContinuousCollector
    return ContinuousCollector(source=log, hostname="SYNTHETIC-WS01", folder=state_dir, session=session,
                               clock=clock or time.monotonic)


def drain(c, limit=200):
    for _ in range(limit):
        result = c.run_once()
        if not (result["live"] or result["backfill"] or result["spool"]):
            return result
    raise AssertionError("collector did not settle")


def get(base, path, **params):
    return requests.get(base + path, params=params, timeout=30).json()


def flagged(base, event_id):
    """Events with this Event ID that are evidence of an active detection (after the engine caught up)."""
    from conftest import drain as engine_drain
    engine_drain()
    return get(base, "/api/timeline/page", event_id=event_id, anomalies_only="true")["total"]


def test_new_event_after_startup_is_collected_and_flagged(receiver, state_dir):
    log = make_log()
    log.write("Security", 4624, NOW() - timedelta(hours=2), count=50)
    c = collector(log, state_dir)
    drain(c)
    top = get(receiver, "/api/timeline/page", limit=1)["top_cursor"]
    written = time.time()
    log.write("Security", 4720, data={"TargetUserName": "created-after-start"})
    c.run_once()                                                     # one live pass (default every 2 s)
    newer = get(receiver, "/api/timeline/page", newer_than=top)["items"]
    assert [i["event_id"] for i in newer] == [4720]
    assert time.time() - written < 2
    assert flagged(receiver, 4720) == 1
    event = requests.get(receiver + f"/api/events/{newer[0]['id']}").json()
    assert event["collected_at"] and event["event_time"] and event["received_at"]   # times recorded separately


def test_live_events_are_not_blocked_by_history(receiver, state_dir, monkeypatch):
    import agent.continuous as continuous
    monkeypatch.setattr(continuous, "BACKFILL_BATCH", 500)
    log = make_log()
    log.write("Security", 4624, NOW() - timedelta(hours=1), count=5000)
    c = collector(log, state_dir)
    c.run_once()                                                     # initialise + first backfill slice
    log.write("Security", 1102, data={"SubjectUserName": "live"})
    c.run_once()
    status = c.channels["Security"]
    assert status["backfill"] == "running"                           # history still loading...
    assert flagged(receiver, 1102) == 1   # ...but the live event is already in
    drain(c)
    assert get(receiver, "/api/timeline/page", limit=1)["total"] == 5001       # history completed afterwards


def test_resume_from_saved_position_after_restart(receiver, state_dir):
    log = make_log()
    log.write("Security", 4624, NOW() - timedelta(hours=1), count=300)
    first = collector(log, state_dir)
    drain(first)
    assert first.delivered_total == 300
    first.db.close()
    log.write("Security", 4625, count=3)
    second = collector(log, state_dir)
    drain(second)
    assert second.delivered_total == 3                               # only new events, no historical re-read
    assert get(receiver, "/api/timeline/page", limit=1)["total"] == 303


def test_receiver_store_reset_triggers_history_reread(state_dir, monkeypatch):
    from agent.continuous import ContinuousCollector

    class Session(requests.Session):
        store = "store-a"

        def get(self, url, **kwargs):
            response = requests.Response()
            response.status_code = 200
            response._content = (f'{{"channels": [], "store_id": "{self.store}", "max_ingest_events": 10000}}').encode()
            return response

        def post(self, url, json=None, **kwargs):
            response = requests.Response()
            response.status_code = 202
            response._content = (f'{{"accepted": {len(json.get("events", []))}}}').encode() if "events" in (json or {}) else b"{}"
            return response

    monkeypatch.setenv("LOGPLATFORM_URL", "http://127.0.0.1:9/api/ingest")
    log = make_log()
    log.write("System", 7036, NOW() - timedelta(hours=1), count=20)
    session = Session()
    c = ContinuousCollector(source=log, hostname="SYNTHETIC-WS01", folder=state_dir, session=session)
    drain(c)
    assert c.delivered_total == 20
    session.store = "store-b"                                        # receiver database replaced
    c._next_config = 0
    drain(c)
    assert c.delivered_total == 40


def test_temporary_failures_recover_without_loss(receiver, state_dir):
    clock = [1000.0]
    log = make_log()
    log.write("Security", 4624, NOW() - timedelta(minutes=5), count=10)
    c = collector(log, state_dir, clock=lambda: clock[0])
    drain(c)
    log.fail("Security", "error", "RPC server unavailable (synthetic)")
    log.write("Security", 4720, count=2)
    c.run_once()
    state = c.channels["Security"]
    assert state["state"] == "error" and state["retry_at"] > clock[0] and "RPC" in state["last_error"]
    c._next_health = 0
    c.run_once()
    health = get(receiver, "/api/anomalies/coverage")
    sec = next(ch for ch in health["channels"] if ch["channel"] == "Security")
    assert sec["state"] == "error" and sec["coverage"] == "unavailable"        # failure is visible
    log.fail("Security", None)
    clock[0] += 3600
    drain(c)
    assert c.channels["Security"]["state"] == "ok"
    assert flagged(receiver, 4720) == 2


def test_delivery_failure_keeps_events_spooled(receiver, state_dir):
    class Flaky(requests.Session):
        down = True

        def post(self, url, *args, **kwargs):
            if self.down and url.endswith("/ingest"):
                raise requests.ConnectionError("receiver down (synthetic)")
            return super().post(url, *args, **kwargs)

    session = Flaky()
    log = make_log()
    log.write("Security", 4720, NOW() - timedelta(minutes=2), count=5)
    c = collector(log, state_dir, session=session)
    c.run_once()
    assert c.spool_size() == 5 and "receiver down" in c.last_error
    session.down = False
    drain(c)
    assert c.spool_size() == 0 and flagged(receiver, 4720) == 5


def test_lost_records_and_cleared_logs_are_reported(receiver, state_dir):
    log = make_log()
    log.write("Security", 4624, NOW() - timedelta(minutes=30), count=10)
    c = collector(log, state_dir)
    drain(c)
    log.write("Security", 4624, count=20)
    log.overwrite_oldest("Security", 20)        # records 11-20 overwritten before the collector looked
    drain(c)
    assert c.channels["Security"]["records_lost"] == 10
    log.clear("Security")
    log.write("Security", 1102, data={"SubjectUserName": "cleaner"})
    drain(c)
    assert flagged(receiver, 1102) == 1     # first record after a clear is read
    c._next_health = 0
    c.run_once()
    sec = next(ch for ch in get(receiver, "/api/anomalies/coverage")["channels"] if ch["channel"] == "Security")
    assert sec["coverage"] == "partial" and sec["records_lost"] == 10
    assert any("overwritten or cleared" in reason for reason in sec["coverage_reasons"])


def test_unavailable_and_disabled_channels_are_reported(receiver, state_dir):
    log = make_log()
    log.logs.pop("Setup")                                            # channel missing on this host
    log.fail("Application", "access_denied", "Attempted to perform an unauthorized operation.")
    c = collector(log, state_dir)
    drain(c)
    c._next_health = 0
    c.run_once()
    channels = {ch["channel"]: ch for ch in get(receiver, "/api/anomalies/coverage")["channels"]}
    assert channels["Setup"]["state"] == "unavailable"
    assert channels["Application"]["state"] == "access_denied"
    assert channels["Microsoft-Windows-Sysmon/Operational"]["state"] == "unavailable"
    assert channels["System"]["state"] == "ok"                      # enabled empty log is monitored


# ----------------------------------------------------------------- coverage
def test_coverage_no_data_is_not_zero_anomalies(client):
    summary = client.get("/api/anomalies/summary").json()
    assert summary["coverage"]["state"] == "no_data"
    assert summary["coverage"]["label"] == "No data collected yet"


def test_partial_retention_and_no_false_complete_claim(client):
    from logplatform import anomalies

    ingest(client, [synthetic.envelope(4720, "Security", NOW() - timedelta(days=2), 500)])
    base = {"agent_id": "synthetic-a", "hostname": "SYNTHETIC-WS01", "mode": "continuous", "interval_seconds": 2}

    def report(log):
        channels = [{"channel": "Security", "state": "ok", "backfill": "complete", "last_success_at": "2026-10-27T00:00:00Z",
                     **({"log": log} if log else {})}]
        client.post("/api/collector/status", headers=AUTH, json=dict(base, channels=channels))
        anomalies.invalidate_cache()
        return next(c for c in client.get("/api/anomalies/coverage").json()["channels"] if c["channel"] == "Security")

    no_meta = report(None)
    assert no_meta["coverage"] == "partial" and "could not be confirmed" in no_meta["coverage_note"]
    wrapped = report({"enabled": True, "mode": "Circular", "oldest_record": 480, "is_full": True})
    assert wrapped["coverage"] == "partial" and "no longer holds records" in wrapped["coverage_note"]
    pristine = report({"enabled": True, "mode": "Circular", "oldest_record": 1, "is_full": False})
    assert pristine["coverage"] == "verified" and "never wrapped" in pristine["coverage_note"]


def test_stale_collector_marks_coverage_partial(client):
    from logplatform import anomalies, db

    ingest(client, [synthetic.envelope(4720, "Security", NOW() - timedelta(days=8), 1)])
    client.post("/api/collector/status", headers=AUTH, json={
        "agent_id": "synthetic-a", "hostname": "SYNTHETIC-WS01", "mode": "continuous", "interval_seconds": 2,
        "channels": [{"channel": "Security", "state": "ok", "backfill": "complete"}]})
    with db.connect() as connection:
        connection.execute("UPDATE collector_agents SET last_heartbeat = '2026-01-01T00:00:00.000000Z'")
    anomalies.invalidate_cache()
    coverage = client.get("/api/anomalies/coverage").json()
    assert coverage["health"]["state"] == "stale"
    security = next(c for c in coverage["channels"] if c["channel"] == "Security")
    assert security["coverage"] == "partial" and "has not reported since" in security["coverage_note"]
