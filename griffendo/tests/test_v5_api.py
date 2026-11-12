"""v5 API: rule switches and re-evaluation, custom rules, time filters, shared counts, timeline, endpoint, feedback."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import synthetic
from conftest import AUTH, drain, ingest
from v5_events import NOW, Builder

ORIGIN_BAD = {"origin": "http://evil.example"}


def dets(client, **params):
    params.setdefault("range", "all")
    params.setdefault("limit", 500)
    response = client.get("/api/detections", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def with_rule(client, rule_id, **params):
    return [i for i in dets(client, **params)["items"] if rule_id in i["rule_ids"]]


def toggle(client, rule_id, enabled):
    response = client.put(f"/api/detections/rules/{rule_id}/enabled", json={"enabled": enabled})
    assert response.status_code == 200, response.text
    from logplatform.detection.engine.service import service
    service().wait_job(rule_id, 30)
    drain()
    return response.json()


def accounts(b: Builder, start: int, count: int, user_prefix="acct"):
    for i in range(count):
        b.add(4720, "Security", b.at(start + i * 2000), {"TargetUserName": f"{user_prefix}{i}",
                                                          "SubjectUserName": f"admin{i}"})


# ----------------------------------------------------------------- rule switches
def test_switch_off_hides_everywhere_and_switch_on_restores_and_catches_up(client):
    b = Builder(start=NOW() - timedelta(hours=30))
    accounts(b, 0, 3)
    ingest(client, b.events)
    before = len(with_rule(client, "SEC-4720"))
    assert before == 3
    summary_before = client.get("/api/detections/summary").json()["total_active"]
    result = toggle(client, "SEC-4720", False)
    assert result["rule"]["enabled"] is False
    assert with_rule(client, "SEC-4720") == []                                       # active view
    assert client.get("/api/detections/summary").json()["total_active"] < summary_before   # counts
    assert len(with_rule(client, "SEC-4720", scope="inactive")) == 3                 # history kept
    tl = client.get("/api/timeline/detections", params={"range": "7d"}).json()["items"]
    assert not any("SEC-4720" in i["rule_ids"] for i in tl)                           # timeline
    b2 = Builder(start=NOW() - timedelta(hours=3))
    accounts(b2, 0, 2, user_prefix="while_off")                                       # arrives while the rule is off
    ingest(client, b2.events)
    assert with_rule(client, "SEC-4720") == []
    result = toggle(client, "SEC-4720", True)
    assert result["job"]["state"] in ("done", "queued", "running")
    restored = with_rule(client, "SEC-4720")
    assert len(restored) == 5                                                        # 3 restored + 2 caught up
    toggle(client, "SEC-4720", False)
    toggle(client, "SEC-4720", True)
    assert len(with_rule(client, "SEC-4720")) == 5                                    # no duplicates
    stats = next(r for r in client.get("/api/detections/rules", params={"q": "SEC-4720"}).json()["items"])
    assert stats["signals"] == 5 and stats["reevaluated"] == 2


def test_rule_switch_persists_across_restart(state_dir):
    from fastapi.testclient import TestClient
    from logplatform.app import app
    with TestClient(app) as client:
        toggle(client, "SEC-4625", False)
    with TestClient(app) as client:
        rule = client.get("/api/detections/rules/SEC-4625").json()
        assert rule["enabled"] is False
        b = Builder()
        b.logon(b.at(0), "x", "0x0", success=False)
        ingest(client, b.events)
        assert with_rule(client, "SEC-4625") == []


def test_grouping_rules_cannot_be_switched_off_and_writes_refuse_cross_origin(client):
    response = client.put("/api/detections/rules/WAZ-60000/enabled", json={"enabled": False})
    assert response.status_code == 409
    response = client.put("/api/detections/rules/SEC-4720/enabled", json={"enabled": False}, headers=ORIGIN_BAD)
    assert response.status_code == 403
    assert client.post("/api/detections/rules", json={}, headers=ORIGIN_BAD).status_code == 403
    assert client.get("/api/detections/rules/SEC-4720").json()["enabled"] is True


# ----------------------------------------------------------------- custom rules
BASE_RULE = {"name": "Synthetic encoded PowerShell", "severity": "High", "category": "Execution",
             "description": "PowerShell started with an encoded command.", "explanation": "Encoded commands hide intent.",
             "investigation": "Decode the command and review the parent process.", "kind": "single",
             "sources": [{"channel": "Microsoft-Windows-Sysmon/Operational", "event_ids": [1]},
                         {"channel": "Security", "event_ids": [4688]}],
             "condition": {"all": [{"field": "process.name", "op": "eq", "values": ["powershell.exe"], "ci": True},
                                   {"field": "process.args", "op": "eq", "values": ["-enc", "-encodedcommand"], "ci": True},
                                   {"not": {"field": "process.parent.name", "op": "eq", "values": ["ccmexec.exe"], "ci": True}}]},
             "mitre": ["T1059.001"], "rule_id": "CUS-ENC-PS"}


def test_custom_rule_validation_explains_unavailable_fields(client):
    bad = dict(BASE_RULE, condition={"field": "process.code_signature.trusted", "op": "eq", "values": [False]})
    response = client.post("/api/detections/rules/validate", json=bad)
    assert response.status_code == 422 and "not collected" in response.json()["errors"]["condition"]
    wrong_source = dict(BASE_RULE, sources=[{"channel": "Security", "event_ids": [4624]}],
                        condition={"field": "registry.path", "op": "wildcard", "values": ["*\\Run\\*"]})
    message = client.post("/api/detections/rules/validate", json=wrong_source).json()["errors"]["condition"]
    assert "never present in the selected sources" in message and "Sysmon" in message
    regex = dict(BASE_RULE, condition={"field": "process.command_line", "op": "regex", "values": ["(a+)+$"]})
    assert "catastrophic" in client.post("/api/detections/rules/validate", json=regex).json()["errors"]["condition"]
    missing = {k: v for k, v in BASE_RULE.items() if k not in ("name", "investigation")}
    errors = client.post("/api/detections/rules/validate", json=missing).json()["errors"]
    assert {"name", "investigation"} <= set(errors)
    reserved = dict(BASE_RULE, rule_id="ELA-123")
    assert "rule_id" in client.post("/api/detections/rules/validate", json=reserved).json()["errors"]
    assert client.post("/api/detections/rules/validate", json=BASE_RULE).json()["valid"] is True


def test_custom_rule_create_edit_delete_keeps_history(client):
    b = Builder()
    b.security_process(b.at(0), 0x900, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "powershell.exe -enc SQBFAFgA", 0x10, "C:\\Windows\\explorer.exe")
    b.security_process(b.at(5), 0x904, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "powershell.exe -enc SQBFAFgA", 0x11, "C:\\Windows\\CCM\\ccmexec.exe", user="bob")
    ingest(client, b.events)
    created = client.post("/api/detections/rules", json=BASE_RULE)
    assert created.status_code == 201, created.text
    assert created.json()["rule"]["verified"] is False
    drain()
    from logplatform.detection.engine.service import service
    service().wait_job("CUS-ENC-PS", 30)
    hits = with_rule(client, "CUS-ENC-PS")
    assert len(hits) == 1 and hits[0]["user_name"] == "alice"            # the existing event was evaluated; exclusion applied
    assert client.post("/api/detections/rules", json=BASE_RULE).status_code == 409   # duplicate id
    edited = dict(BASE_RULE, condition={"field": "process.name", "op": "eq", "values": ["cmd.exe"], "ci": True})
    assert client.put("/api/detections/rules/CUS-ENC-PS", json=edited).status_code == 200
    service().wait_job("CUS-ENC-PS", 30)
    assert with_rule(client, "CUS-ENC-PS") == []                          # old matches are not the new definition
    history = dets(client, scope="all", rule_id="CUS-ENC-PS")["items"]   # ...but stay findable for the rule
    assert len(history) == 1 and "CUS-ENC-PS" not in history[0]["rule_ids"] and "CUS-ENC-PS" in history[0]["signal_rules"]
    detail = client.get(f"/api/detections/{history[0]['id']}").json()
    mine = next(s for s in detail["signals"] if s["rule_id"] == "CUS-ENC-PS")
    assert mine["rule_state"] == "changed since detection" and mine["rule_name"] == "Synthetic encoded PowerShell"
    assert client.delete("/api/detections/rules/CUS-ENC-PS").status_code == 200
    detail = client.get(f"/api/detections/{history[0]['id']}").json()
    mine = next(s for s in detail["signals"] if s["rule_id"] == "CUS-ENC-PS")
    assert mine["rule_state"] == "deleted" and detail["rules"]["CUS-ENC-PS"]["deleted"]
    assert client.delete("/api/detections/rules/SEC-4720").status_code == 409           # built-in: switch off only


def test_custom_threshold_and_sequence_rules(client):
    threshold = dict(BASE_RULE, rule_id="CUS-MANY-FAIL", name="Many failed logons from one address", kind="threshold",
                     sources=[{"channel": "Security", "event_ids": [4625]}],
                     condition={"field": "event.code", "op": "eq", "values": ["4625"]},
                     threshold={"count": 5, "window_seconds": 120, "by": ["source.ip"]})
    sequence = dict(BASE_RULE, rule_id="CUS-SEQ", name="User created then added to a group", kind="sequence",
                    sources=[{"channel": "Security", "event_ids": [4720, 4732]}], maxspan=600,
                    steps=[{"condition": {"field": "event.code", "op": "eq", "values": ["4720"]}, "by": ["user.name"]},
                           {"condition": {"field": "event.code", "op": "eq", "values": ["4732"]}, "by": ["user.name"]}])
    sequence.pop("condition")
    for payload in (threshold, sequence):
        response = client.post("/api/detections/rules", json=payload)
        assert response.status_code == 201, response.text
    b = Builder()
    for i in range(5):
        b.logon(b.at(i * 10), f"u{i}", "0x0", success=False, ip="198.51.100.9")
    for i in range(4):
        b.logon(b.at(i * 10), f"v{i}", "0x0", success=False, ip="198.51.100.10")
    b.add(4720, "Security", b.at(100), {"SubjectUserName": "eve", "TargetUserName": "tmp"})
    b.add(4732, "Security", b.at(160), {"SubjectUserName": "eve", "TargetUserName": "Administrators", "MemberName": "-"})
    ingest(client, b.events)
    assert len(with_rule(client, "CUS-MANY-FAIL")) == 1
    assert len(with_rule(client, "CUS-SEQ")) == 1


# ----------------------------------------------------------------- time filters
def test_event_explorer_time_filter_is_applied_in_the_query(client):
    now = NOW()
    events = [synthetic.envelope(4624, "Security", now - timedelta(minutes=m), m, data={"TargetUserName": "t"})
              for m in (5, 30, 90, 600, 3000)]
    ingest(client, events)
    assert client.get("/api/events", params={"range": "15m"}).json()["total"] == 1
    assert client.get("/api/events", params={"range": "1h"}).json()["total"] == 2
    assert client.get("/api/events", params={"range": "24h"}).json()["total"] == 4
    assert client.get("/api/events").json()["total"] == 5
    start = (now - timedelta(minutes=100)).isoformat()
    end = (now - timedelta(minutes=20)).isoformat()
    page = client.get("/api/events", params={"start": start, "end": end, "limit": 1}).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    second = client.get("/api/events", params={"start": start, "end": end, "limit": 1, "offset": 1}).json()
    assert second["items"][0]["id"] != page["items"][0]["id"]               # pagination respects the range
    assert client.get("/api/events", params={"start": end, "end": start}).status_code == 422
    assert client.get("/api/events", params={"start": "yesterday"}).status_code == 422
    local = (now - timedelta(minutes=25)).astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
    assert client.get("/api/events", params={"start": local}).json()["total"] == 1   # offsets converted to UTC


def test_detection_time_filters_counts_and_columns_agree(client):
    b = Builder(start=NOW() - timedelta(days=3))
    b.add(1102, "Security", b.at(0), {"SubjectUserName": "a"}, provider="Microsoft-Windows-Eventlog")
    b2 = Builder(start=NOW() - timedelta(minutes=40))
    b2.add(4720, "Security", b2.at(0), {"SubjectUserName": "b", "TargetUserName": "n"})
    b2.add(6416, "Security", b2.at(1), {"DeviceDescription": "USB", "SubjectUserName": "c"})
    ingest(client, b.events + b2.events)
    week = client.get("/api/detections/summary", params={"range": "7d"}).json()
    hour = client.get("/api/detections/summary", params={"range": "1h"}).json()
    assert week["total_active"] > hour["total_active"] >= 2
    listed = dets(client, range="1h")["total"]
    assert listed == hour["total_active"]
    for column in week["columns"].values():
        sevs = ",".join(column["severities"])
        assert dets(client, range="7d", severity=sevs)["total"] == column["total"]
    assert client.get("/api/detections", params={"range": "2y"}).status_code == 422
    custom = dets(client, start=(NOW() - timedelta(days=4)).isoformat(), end=(NOW() - timedelta(days=2)).isoformat())
    assert custom["total"] >= 1 and all(1102 in i["event_ids"] for i in custom["items"])


# ----------------------------------------------------------------- overview, endpoint, timeline
def test_overview_endpoint_and_existing_endpoints(client):
    ingest(client, synthetic.demo_dataset())
    overview = client.get("/api/overview", params={"tz_offset": 330}).json()
    assert {"totals", "trend", "event_ids", "channels", "processes", "activity_24h"} <= set(overview)
    assert overview["totals"]["events"] == len(synthetic.demo_dataset())
    summary = client.get("/api/detections/summary").json()
    assert summary["overall_status"] == "attention" and summary["latest_detection"]
    endpoint = client.get("/api/endpoint").json()
    assert endpoint["hosts"][0]["hostname"] == "SYNTHETIC-WS01"
    assert endpoint["detections"]["counts"] == summary["counts"]                 # same summary service
    assert {o["source"] for o in endpoint["optional_sources"]} == {"Sysmon", "Windows Defender", "PowerShell Operational"}
    hosts = client.get("/api/hosts").json()
    assert hosts[0]["events"] == overview["totals"]["events"]
    for path in ("/api/events", "/api/processes", "/api/timeline", "/api/timeline/page", "/api/collector/health",
                 "/api/anomalies/coverage", "/api/live", "/api/config"):
        assert client.get(path).status_code == 200, path


def test_timeline_is_oldest_first_and_pages_without_duplicates(client):
    b = Builder(start=NOW() - timedelta(days=5))
    for i in range(30):
        b.add(4720, "Security", b.at(i * 3600), {"SubjectUserName": f"admin{i}", "TargetUserName": f"n{i}"})
    ingest(client, b.events)
    page = client.get("/api/timeline/detections", params={"limit": 10}).json()
    seen, times = [], []
    while True:
        seen += [i["id"] for i in page["items"]]
        times += [i["det_time"] for i in page["items"]]
        if not page["has_newer"]:
            break
        page = client.get("/api/timeline/detections", params={"limit": 10, "after": page["newer_cursor"]}).json()
    assert len(seen) == len(set(seen)) == page["total"] >= 30 and times == sorted(times)
    newest = client.get("/api/timeline/detections", params={"limit": 10, "position": "end"}).json()
    assert newest["items"][-1]["id"] == seen[-1] and newest["has_older"]
    older = client.get("/api/timeline/detections", params={"limit": 10, "before": newest["older_cursor"]}).json()
    assert older["items"][-1]["det_time"] <= newest["items"][0]["det_time"]
    assert client.get("/api/timeline/detections", params={"after": "garbage"}).status_code == 422


# ----------------------------------------------------------------- feedback
def test_status_and_verdict_persist_across_restart(state_dir):
    from fastapi.testclient import TestClient
    from logplatform.app import app
    with TestClient(app) as client:
        b = Builder()
        b.add(4720, "Security", b.at(0), {"SubjectUserName": "a", "TargetUserName": "n"})
        ingest(client, b.events)
        item = dets(client)["items"][0]
        assert client.post(f"/api/detections/{item['id']}/status", json={"status": "Investigating", "note": "looking"}).status_code == 200
        assert client.post(f"/api/detections/{item['id']}/verdict", json={"verdict": "true_positive"}).status_code == 200
        assert client.post(f"/api/detections/{item['id']}/verdict", json={"verdict": "maybe"}).status_code == 422
        assert client.post(f"/api/detections/{item['id']}/status", json={"status": "Done"}).status_code == 422
    with TestClient(app) as client:
        detail = client.get(f"/api/detections/{item['id']}").json()
        assert detail["status"] == "Investigating" and detail["verdict"] == "true_positive"
        assert detail["verdicts"][0]["verdict"] == "true_positive" and detail["status_history"][0]["note"] == "looking"
        assert dets(client, verdict="true_positive")["total"] == 1 and dets(client, status="Investigating")["total"] == 1


def test_detail_contains_every_section(client):
    b = Builder()
    for i in range(10):
        b.logon(b.at(i), "detail", "0x0", success=False)
    b.logon(b.at(20), "detail", "0xd1")
    ingest(client, b.events)
    item = next(i for i in dets(client)["items"] if "COR-001" in i["rule_ids"])
    detail = client.get(f"/api/detections/{item['id']}").json()
    assert detail["title"] and detail["explanation"] and detail["severity_bands"]           # 1, 3
    assert any(s["details"].get("sequence") for s in detail["signals"])                      # 2, 5
    assert detail["rules"]["COR-001"]["condition"]                                           # 4
    assert len(detail["events"]) == 11 and len(detail["timeline"]) >= 11                     # 6, 7
    assert detail["investigation"]                                                           # 8
    assert "verdicts" in detail and "status_history" in detail                               # 9


def test_manual_refresh_without_collector_reports_honestly(client):
    response = client.post("/api/refresh").json()
    assert response["ok"] is False and response["collection"]["state"] == "unavailable"
    assert "detection_backlog" in response["collection"]
