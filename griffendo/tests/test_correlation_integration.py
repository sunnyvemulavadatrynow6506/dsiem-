"""End-to-end correlation tests: events in through the real receiver, episodes out through the API.

These are the regression tests for the defect that motivated the v6 engine: the v5 grouping
raised one detection per matching event, so 40 failed logons from one address produced 40
detections and repetition was invisible in the score.  Every test here drives the real
pipeline (ingest -> normalize -> rule match -> correlate -> store -> API).
"""
from __future__ import annotations

import pytest

from conftest import AUTH, drain
from v5_events import Builder

SECURITY = "Security"


def detected(client, **params):
    params.setdefault("range", "all")
    params.setdefault("limit", 500)
    response = client.get("/api/detections", params=params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def failed_logon(b, when, user, ip=None, logon_type="3", status="0xc000006d"):
    """One failed logon (4625) as Windows writes it."""
    return b.add(4625, SECURITY, when, {"TargetUserName": user, "TargetDomainName": "LAB",
                                        "LogonType": logon_type, "IpAddress": ip or "-",
                                        "Status": status, "SubStatus": "0xc000006a",
                                        "WorkstationName": "SYNTH-REMOTE",
                                        "TargetUserSid": "S-1-5-21-1-2-3-1001"})


def brute_force(b, count, start=0, step=20, user="admin", ip="203.0.113.9"):
    """``count`` failed logons from one account and one source address."""
    return [failed_logon(b, b.at(start + i * step), user, ip) for i in range(count)]


def test_repeated_failures_from_one_source_are_one_detection(client):
    """40 failed logons from one address = ONE episode carrying 40 occurrences.

    This is the exact v5 defect: it produced 40 separate detections of one event each.
    """
    b = Builder()
    from conftest import ingest
    ingest(client, brute_force(b, 40))
    items = detected(client, rule_id="SEC-4625")
    assert len(items) == 1, f"expected one correlated detection, got {len(items)}"
    episode = items[0]
    assert episode["occurrence_count"] == 40
    assert episode["event_count"] == 40
    assert episode["scope"] == "account admin from 203.0.113.9"


def test_separate_incidents_are_not_merged(client):
    """Different accounts and different addresses must never join one episode."""
    from conftest import ingest
    b = Builder()
    events = brute_force(b, 3, user="admin", ip="203.0.113.9")
    events += brute_force(b, 3, start=1000, user="admin", ip="198.51.100.4")   # other source
    events += brute_force(b, 3, start=2000, user="bob", ip="203.0.113.9")     # other account
    ingest(client, events)
    items = detected(client, rule_id="SEC-4625")
    assert len(items) == 3, "each account/source pair is its own incident"
    assert sorted(item["occurrence_count"] for item in items) == [3, 3, 3]


def test_isolated_events_days_apart_stay_separate(client):
    """Time distance still separates incidents: three failures days apart are three detections."""
    from conftest import ingest
    b = Builder()
    events = [failed_logon(b, b.at(i * 2 * 86400), "alice", logon_type="2") for i in (0, 1, 2)]
    ingest(client, events)
    items = detected(client, rule_id="SEC-4625")
    assert len(items) == 3
    assert all(item["occurrence_count"] == 1 for item in items)


def test_repetition_escalates_score_but_one_event_does_not(client):
    """A burst scores above a single failure; the explanation states why."""
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 40))
    single_b = Builder()
    ingest(client, [failed_logon(single_b, single_b.at(90 * 86400), "carol", logon_type="2")])
    burst = [i for i in detected(client, rule_id="SEC-4625") if i["occurrence_count"] > 1]
    assert burst, "the burst must be present"
    episode = burst[0]
    assert episode["escalated"] is True
    assert episode["score"] > episode["base_score"]
    detail = client.get(f"/api/detections/{episode['id']}").json()
    assert "Repetition adds" in detail["explanation"]


def test_dashboard_counts_match_detection_records(client):
    """Every number on the summary must come from stored detections (no invented statistics)."""
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 5))
    summary = client.get("/api/detections/summary", params={"range": "all"}).json()
    items = detected(client)
    assert summary["total_active"] == len(items)
    for severity, count in summary["counts"].items():
        assert count == len([i for i in items if i["severity"] == severity])


def test_detection_evidence_links_to_the_contributing_events(client):
    """An episode must carry the events that caused it, so it can be investigated."""
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 6))
    episode = detected(client, rule_id="SEC-4625")[0]
    detail = client.get(f"/api/detections/{episode['id']}").json()
    assert detail["signals"], "the episode must keep its signals"
    assert len(detail["timeline"]) == 6, "all six contributing events must be listed"
    assert len(detail["events"]) == 6, "and their full evidence must be retrievable"


def test_analyst_status_survives_a_new_event(client):
    """A later event updates the episode but must not reset the analyst's decision."""
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 2))
    episode = detected(client, rule_id="SEC-4625")[0]
    response = client.post(f"/api/detections/{episode['id']}/status",
                            json={"status": "Investigating", "note": "reviewing"}, headers=AUTH)
    assert response.status_code == 200, response.text
    ingest(client, brute_force(b, 1, start=100))         # same incident, continues
    after = client.get(f"/api/detections/{episode['id']}").json()
    assert after["status"] == "Investigating", "an analyst decision must not be overwritten"
    assert after["occurrence_count"] == 3, "the episode still absorbed the new evidence"


def test_threshold_rule_does_not_consume_and_go_silent(client):
    """A threshold rule keeps reporting after it first fires (v5 consumed the events)."""
    # WAZ-60724 (application faulted) is a plain single rule; use a burst of 4625 through
    # the occurrence machinery instead: after the requirement is met, later events still count.
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 3))
    first = detected(client, rule_id="SEC-4625")[0]["occurrence_count"]
    ingest(client, brute_force(b, 3, start=500))
    second = detected(client, rule_id="SEC-4625")[0]["occurrence_count"]
    assert second > first, "later occurrences must keep being counted"


def test_rules_page_rule_still_reports_its_detections(client):
    """Rule management stays consistent: a rule's detection count matches the detection list."""
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 4))
    rules = client.get("/api/detections/rules", params={"q": "SEC-4625"}).json()["items"]
    assert rules
    rule = rules[0]
    listed = detected(client, rule_id="SEC-4625")
    assert rule["active_detections_7d"] == len([i for i in listed if i["active"]])


def test_true_negative_no_detection_without_a_rule_match(client):
    """Events nobody has a rule for must not create detections (no false positives)."""
    from conftest import ingest
    b = Builder()
    # 4634 (logoff) has no alerting rule in the catalog by itself beyond Wazuh's noise rules.
    ingest(client, [b.logon(b.at(i * 30), "dave", "0x99", logon_type="2", ip="-") for i in range(5)])
    items = [i for i in detected(client) if i["primary_rule_id"] == "SEC-4625"]
    assert items == [], "successful logons must never be reported as failed logons"


# ------------------------------------------------------------------ process lineage
def test_process_lineage_reports_exact_and_probable_links(client):
    """Process trees must separate Sysmon GUID links (exact) from 4688 PID links (probable)."""
    from conftest import ingest
    b = Builder()
    parent = b.process(b.at(0), "aaaa", 1000, r"C:\Program Files\Office\WINWORD.EXE", "WINWORD.EXE /n x.docm",
                       "root", 4, r"C:\Windows\explorer.exe")
    child = b.process(b.at(5), "bbbb", 2000, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "powershell.exe -enc AAAA", "aaaa", 1000, r"C:\Program Files\Office\WINWORD.EXE")
    ingest(client, [parent, child])
    data = client.get("/api/process-lineage").json()
    names = {node["name"].lower() for node in data["nodes"]}
    assert "winword.exe" in names and "powershell.exe" in names
    child_node = next(n for n in data["nodes"] if n["name"].lower() == "powershell.exe")
    assert child_node["parent"]["name"].lower() == "winword.exe"
    assert child_node["parent"]["exact"] is True, "a Sysmon GUID parent link is exact evidence"
    assert data["totals"]["exact_edges"] >= 1
    assert "reused PID" in data["note"], "the caveat for PID-only links must be stated to the analyst"


def test_security_4688_parent_link_is_marked_probable_not_exact(client):
    """4688 carries PIDs only, so its parent link must never be presented as certain."""
    from conftest import ingest
    b = Builder()
    parent = b.security_process(b.at(0), 0x100, r"C:\Windows\System32\cmd.exe", "cmd.exe", 0x10, r"C:\x\p.exe")
    ingest(client, [parent])
    data = client.get("/api/process-lineage").json()
    edges = [node["parent"] for node in data["nodes"] if node.get("parent")]
    assert edges and all(edge["exact"] is False for edge in edges)
    assert data["totals"]["probable_edges"] >= 1


def test_staged_rule_escalates_through_its_stages_end_to_end(client):
    """A DSIEM directive stage walk, through the real pipeline and the API.

    SEC-4625 declares three stages (reliability 1 / 6 / 9 at 1 / 10 / 100 occurrences), so a
    single failure is stage 1 and a long burst reaches stage 3 -- on the *same* episode.
    """
    from conftest import ingest
    quiet = Builder()
    ingest(client, [failed_logon(quiet, quiet.at(90 * 86400), "zoe", logon_type="2")])
    burst = Builder()
    ingest(client, brute_force(burst, 120))

    items = detected(client, rule_id="SEC-4625")
    single = [i for i in items if i["occurrence_count"] == 1][0]
    heavy = [i for i in items if i["occurrence_count"] == 120][0]

    # Stage 1 is reachable by the first occurrence, so a lone failure is staged at stage 1 with
    # reliability 1 -> score 10; that is DSIEM's low-reliability first alarm.
    assert single["staged"] is True and single["stage"] == 1
    assert single["stages"]["SEC-4625"]["score"] == 10
    assert heavy["staged"] is True
    assert heavy["stage"] == 3
    stage = heavy["stages"]["SEC-4625"]
    assert (stage["stage"], stage["stages"], stage["reliability"]) == (3, 3, 9)
    assert stage["next_occurrence"] is None
    assert stage["score"] == 90
    assert heavy["score"] >= stage["score"], "the stage score must reach the episode score"
    assert heavy["score"] > single["score"]

    detail = client.get(f"/api/detections/{heavy['id']}").json()
    assert "Stage 3 of 3" in detail["explanation"]
    assert detail["stage"] == 3
    # The episode is still one row: staging escalates, it does not split the incident.
    assert len([i for i in items if i["scope"] == "account admin from 203.0.113.9"]) == 1


def test_detection_detail_exposes_each_rules_correlation_block(client):
    """The detail view must show why a detection correlated, including its DSIEM stages.

    Regression: the per-rule payload in a detection used a field whitelist that omitted
    ``correlation``, so a staged episode showed stage data but no sign of the stage
    definition next to the contributing rule.
    """
    from conftest import ingest
    b = Builder()
    ingest(client, brute_force(b, 12))
    episode = detected(client, rule_id="SEC-4625")[0]
    detail = client.get(f"/api/detections/{episode['id']}").json()
    block = detail["rules"]["SEC-4625"]["correlation"]
    assert block["type"] == "staged"
    assert [stage["reliability"] for stage in block["stages"]] == [1, 6, 9]
    assert block["stages"][1]["occurrence"] == 10
