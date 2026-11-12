"""Detection and Correlation Engine (v5): normalizer, condition language, correlation, behaviour model, decisions."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

import synthetic
from conftest import AUTH, drain, ingest
from v5_events import NOW, SYSMON, Builder, guid


def detections(client, **params):
    params.setdefault("range", "all")
    params.setdefault("limit", 500)
    response = client.get("/api/detections", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def rule_ids(client, **params):
    found = set()
    for item in detections(client, **params)["items"]:
        found.update(item["rule_ids"])
    return found


# ----------------------------------------------------------------- normalizer
def test_normalizer_maps_sysmon_and_security_fields():
    from logplatform.detection.engine import normalizer
    from logplatform.parser import parse_event

    b = Builder()
    sysmon = b.process(b.at(0), guid(2), 200, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       'powershell.exe -nop -c "Get-Item x"', guid(1), 100, "C:\\Program Files\\Office\\WINWORD.EXE",
                       OriginalFileName="PowerShell.EXE", Hashes="SHA256=AB12,MD5=CD34", CurrentDirectory="-")
    sec = b.security_process(b.at(1), 0x1a4, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", 0x10, "C:\\x\\p.exe")
    logon = b.logon(b.at(2), "bob", "0xbeef", logon_type="10", ip="::ffff:198.51.100.4")
    rows = []
    for index, event in enumerate((sysmon, sec, logon)):
        parsed = parse_event(event["xml"])
        rows.append({"id": event["id"], "hostname": "SYNTHETIC-WS01", "channel": event["channel"], "record_id": index,
                     "event_time": synthetic.system_time(b.at(index)), "normalized_json": json.dumps(parsed),
                     "provider": parsed["provider"], "event_id": parsed["event_id"], "collected_at": None})
    ev = normalizer.normalize(rows[0])
    assert ev["process.name"] == "powershell.exe" and ev["process.parent.name"] == "WINWORD.EXE"
    assert ev["process.args"] == ["powershell.exe", "-nop", "-c", "Get-Item x"] and ev["process.args_count"] == 4
    assert ev["process.entity_id"] == guid(2) and ev["process.parent.pid"] == 100
    assert ev["process.pe.original_file_name"] == "PowerShell.EXE" and ev["process.hash.sha256"] == "ab12"
    assert ev["user.name"] == "alice" and ev["user.domain"] == "LAB" and ev["event.type"] == ["start"]
    assert "process.working_directory" not in ev                     # "-" placeholder means missing, not a value
    assert normalizer.get(ev, "winlog.event_data.CurrentDirectory") == "-"   # ...the raw value is still there
    ev = normalizer.normalize(rows[1])
    assert ev["process.pid"] == 0x1a4 and ev["process.parent.pid"] == 0x10 and ev["process.parent.name"] == "p.exe"
    assert ev["user.id"] == "S-1-5-21-1-2-3-1001" and ev["winlog.logon.id"] == "0x5555"
    ev = normalizer.normalize(rows[2])
    assert ev["winlog.logon.type"] == "RemoteInteractive" and ev["source.ip"] == "198.51.100.4"
    assert ev["event.action"] == "logged-in" and ev["user.name"] == "bob"


def test_windows_command_line_splitting_matches_commandlinetoargvw():
    from logplatform.detection.engine.normalizer import split_command_line
    assert split_command_line('"C:\\Program Files\\a.exe" -x "two words"') == ["C:\\Program Files\\a.exe", "-x", "two words"]
    assert split_command_line('a.exe "C:\\path with\\\\" next') == ["a.exe", "C:\\path with\\", "next"]
    assert split_command_line('a.exe \\"quoted\\" x\\\\y') == ["a.exe", '"quoted"', "x\\\\y"]
    assert split_command_line("") == []


# ----------------------------------------------------------------- condition language
def test_condition_language_semantics_and_validation():
    from logplatform.detection.engine import conditions as c

    ev = {"_lower": {}, "process.name": "PowerShell.exe", "process.args": ["powershell.exe", "-enc", "AAAA"],
          "powershell.file.script_block_text": "IEX (New-Object Net.WebClient).DownloadString('x')"}
    check = lambda node: c.compile_condition(node)(ev)  # noqa: E731
    assert check({"field": "process.name", "op": "eq", "values": ["powershell.exe"], "ci": True})
    assert not check({"field": "process.name", "op": "eq", "values": ["powershell.exe"]})          # case-sensitive
    assert check({"field": "process.args", "op": "eq", "values": ["-enc"]})                          # any element
    assert not check({"field": "user.name", "op": "eq", "values": ["x"]})                             # missing -> false
    assert check({"not": {"field": "user.name", "op": "eq", "values": ["x"]}})                         # exclusion on missing
    assert check({"field": "process.name", "op": "wildcard", "values": ["power*.EXE"], "ci": True})
    assert not check({"field": "process.name", "op": "regex", "values": ["Power"]})                   # anchored
    assert check({"field": "powershell.file.script_block_text", "op": "phrase", "values": ["net webclient"]})
    assert check({"fn": "length", "field": "process.name", "op": "gte", "value": 10})
    assert c.validate({"field": "x", "op": "regex", "values": ["(a+)+"]})                            # ReDoS refused
    assert c.validate({"field": "x", "op": "nope", "values": ["1"]})
    assert c.validate({"field": "x", "op": "regex", "values": ["("]})
    assert c.validate({"all": []})
    assert not c.validate({"all": [{"field": "event.code", "op": "eq", "values": ["4624"]}]})


# ----------------------------------------------------------------- deterministic rules and correlation
def test_single_event_rule_fires_and_reprocessing_does_not_duplicate(client):
    event = synthetic.envelope(4720, "Security", NOW() - timedelta(minutes=5), 1,
                               data={"TargetUserName": "svc_new", "SubjectUserName": "synthetic.admin"})
    ingest(client, [event])
    first = detections(client)["total"]
    ingest(client, [event])                                 # same event delivered again
    from logplatform.detection.engine.service import service
    service().process_rows([])                              # nothing new
    assert detections(client)["total"] == first and "SEC-4720" in rule_ids(client)


def test_failed_logons_then_success_sequence(client):
    b = Builder()
    for i in range(10):
        b.logon(b.at(i * 5), "victim", "0x0", success=False)
    b.logon(b.at(60), "victim", "0xaaa1")
    for i in range(9):                                      # only 9 failures for this account: no detection
        b.logon(b.at(100 + i), "other", "0x0", success=False)
    b.logon(b.at(130), "other", "0xaaa2")
    for i in range(10):                                     # 10 failures, but the success is 10 minutes later
        b.logon(b.at(400 + i), "late", "0x0", success=False)
    b.logon(b.at(1100), "late", "0xaaa3")
    ingest(client, b.events)
    items = [i for i in detections(client)["items"] if "COR-001" in i["rule_ids"]]
    assert len(items) == 1 and items[0]["user_name"] == "victim" and items[0]["severity"] == "High"
    detail = client.get(f"/api/detections/{items[0]['id']}").json()
    seq = next(s for s in detail["signals"] if s["rule_id"] == "COR-001")
    assert len(seq["details"]["sequence"]) == 11 and seq["details"]["join"] == {"user.name": "victim"}


def office_chain(b: Builder, base: int, offset: float = 0, interpreter_parent_guid: int | None = None):
    office = b.process(b.at(offset), guid(base + 1), base + 1, "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                       "WINWORD.EXE /n invoice.docm", guid(base), base, "C:\\Windows\\explorer.exe")
    parent = interpreter_parent_guid if interpreter_parent_guid is not None else base + 1
    shell = b.process(b.at(offset + 4), guid(base + 2), base + 2,
                      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden",
                      guid(parent), parent, "C:\\Program Files\\Microsoft Office\\WINWORD.EXE")
    task = b.process(b.at(offset + 9), guid(base + 3), base + 3, "C:\\Windows\\System32\\schtasks.exe",
                     "schtasks.exe /create /tn Updater /tr C:\\Users\\alice\\x.exe /sc onlogon", guid(base + 2), base + 2,
                     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    return office, shell, task


def test_chain_office_to_interpreter_to_scheduled_task(client):
    b = Builder()
    office_chain(b, 100)
    # Same programs, same minute, but the interpreter's parent is an unrelated process: not a chain.
    office_chain(b, 200, offset=1, interpreter_parent_guid=999)
    ingest(client, b.events)
    chains = [i for i in detections(client)["items"] if "CHN-001" in i["rule_ids"]]
    assert len(chains) == 1
    detail = client.get(f"/api/detections/{chains[0]['id']}").json()
    chain_signals = [s for s in detail["signals"] if s["rule_id"] == "CHN-001"]
    assert len(chain_signals) == 1                   # the second, unrelated tree is not joined by time or session
    links = chain_signals[0]["details"]["chain"]
    assert [l["process"] for l in links] == ["WINWORD.EXE", "powershell.exe", "schtasks.exe"]
    assert links[1]["via"] == "child process" and links[2]["via"] in ("child process", "same process")
    assert detail["timeline"] and [t["time"] for t in detail["timeline"]] == sorted(t["time"] for t in detail["timeline"])


def test_chain_with_missing_process_identifiers_is_safe(client):
    b = Builder()
    b.add(1, SYSMON, b.at(0), {"Image": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"})      # no GUID / PID
    b.add(1, SYSMON, b.at(2), {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "WINWORD.EXE"})
    b.add(1, SYSMON, b.at(3), {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn x"})
    ingest(client, b.events)
    assert "CHN-001" not in rule_ids(client)            # no lineage information -> no chain claimed


def test_chain_interpreter_writes_run_key(client):
    b = Builder()
    b.process(b.at(0), guid(301), 301, "C:\\Windows\\System32\\cmd.exe", "cmd /c reg add", guid(300), 300,
              "C:\\Windows\\explorer.exe")
    b.add(13, SYSMON, b.at(5), {"EventType": "SetValue", "ProcessGuid": "{%s}" % guid(301), "ProcessId": "301",
                                "Image": "C:\\Windows\\System32\\cmd.exe",
                                "TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                                "Details": "C:\\Users\\alice\\upd.exe"})
    b.add(13, SYSMON, b.at(6), {"EventType": "SetValue", "ProcessGuid": "{%s}" % guid(999), "ProcessId": "999",
                                "Image": "C:\\Program Files\\Vendor\\agent.exe",
                                "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\vendor",
                                "Details": "C:\\Program Files\\Vendor\\agent.exe"})
    ingest(client, b.events)
    chains = [i for i in detections(client)["items"] if "CHN-004" in i["rule_ids"]]
    assert len(chains) == 1 and chains[0]["process_name"] == "cmd.exe"


def test_chain_service_install_then_its_program_runs(client):
    b = Builder()
    b.add(7045, "System", b.at(0), {"ServiceName": "SynthSvc", "ImagePath": "C:\\ProgramData\\synth\\svc.exe",
                                    "AccountName": "LocalSystem"}, provider="Service Control Manager")
    b.security_process(b.at(30), 0x700, "C:\\ProgramData\\synth\\svc.exe", "svc.exe", 0x2a0,
                       "C:\\Windows\\System32\\services.exe", user="SYSTEM", logon="0x3e7")
    b.add(7045, "System", b.at(50), {"ServiceName": "Other", "ImagePath": "C:\\Other\\o.exe"}, provider="Service Control Manager")
    b.security_process(b.at(60), 0x704, "C:\\Different\\o.exe", "o.exe", 0x2a0, "C:\\Windows\\System32\\services.exe",
                       user="SYSTEM", logon="0x3e7")
    ingest(client, b.events)
    detail_ids = [i["id"] for i in detections(client)["items"] if "CHN-003" in i["rule_ids"]]
    assert len(detail_ids) == 1
    detail = client.get(f"/api/detections/{detail_ids[0]}").json()
    chain = next(s for s in detail["signals"] if s["rule_id"] == "CHN-003")["details"]["chain"]
    assert chain[1]["via"] == "process.executable = file.path"


def test_remote_logon_then_admin_change_same_session_only(client):
    b = Builder()
    b.logon(b.at(0), "mallory", "0xc0ffee", logon_type="3")
    b.add(4720, "Security", b.at(60), {"SubjectUserName": "mallory", "SubjectLogonId": "0xc0ffee", "TargetUserName": "backdoor"})
    b.logon(b.at(100), "admin2", "0xd00d", logon_type="10")
    b.add(4720, "Security", b.at(160), {"SubjectUserName": "admin2", "SubjectLogonId": "0xbeef", "TargetUserName": "x"})
    ingest(client, b.events)
    hits = [i for i in detections(client)["items"] if "CHN-005" in i["rule_ids"]]
    assert len(hits) == 1 and hits[0]["user_name"] == "mallory"


def test_out_of_order_arrival_still_correlates(client):
    b = Builder()
    for i in range(10):
        b.logon(b.at(i), "ooo", "0x0", success=False)
    b.logon(b.at(30), "ooo", "0xab")
    b.events.reverse()                                   # newest first, like the historical backfill
    ingest(client, b.events)
    assert "COR-001" in rule_ids(client)


def test_wazuh_frequency_rule(client):
    b = Builder()
    for i in range(7):
        b.add(1000, "Application", b.at(i), {"param1": "app.exe"}, provider="Application Error", level=2)
    ingest(client, b.events)
    assert "WAZ-61061" not in rule_ids(client)          # 7 errors: below Wazuh's frequency of 8
    b2 = Builder()
    b2.add(1000, "Application", b.at(8), {"param1": "app.exe"}, provider="Application Error", level=2)
    ingest(client, b2.events)
    detail = [i for i in detections(client)["items"] if "WAZ-61061" in i["rule_ids"]]
    assert len(detail) == 1


# ----------------------------------------------------------------- aggregation and scoring
def test_same_event_matched_by_several_rules_is_one_detection(client):
    event = synthetic.envelope(1102, "Security", NOW() - timedelta(minutes=3), 9,
                               data={"SubjectUserName": "cleaner", "SubjectDomainName": "LAB"},
                               provider="Microsoft-Windows-Eventlog", user_data=True)
    ingest(client, [event])
    items = [i for i in detections(client)["items"] if 1102 in i["event_ids"]]
    assert len(items) == 1 and len(items[0]["rule_ids"]) >= 2
    detail = client.get(f"/api/detections/{items[0]['id']}").json()
    # The extra rules corroborate; the same event is not counted as independent evidence.
    assert items[0]["score"] == max(s["score"] for s in detail["signals"])
    assert "corroboration" in detail["explanation"]


def test_unrelated_events_are_not_merged_by_time():
    from logplatform.detection.engine import aggregator
    a = {"user.name": "alice", "winlog.logon.id": "0x1", "_lower": {}}
    b = {"user.name": "bob", "winlog.logon.id": "0x2", "_lower": {}}
    system = {"user.name": "SYSTEM", "winlog.logon.id": "0x3e7", "user.id": "S-1-5-18", "_lower": {}}
    assert aggregator.entity_key(a) != aggregator.entity_key(b)
    assert aggregator.entity_key(system) is None             # SYSTEM never joins unrelated activity


def test_risk_scale_and_noisy_or_combination():
    from logplatform.detection.engine import risk
    assert [risk.severity_for(s) for s in (99, 73, 47, 21, 10)] == ["Critical", "High", "Medium", "Low", "Informational"]
    assert risk.rule_score("Medium", 99) == 69 and risk.rule_score("High", None) == 75   # kept inside its band
    now = "2026-10-30T10:00:00.000000Z"
    one = {"id": "a", "rule_id": "R1", "score": 50, "last_time": now, "event_keys": ["e1"], "source": "rule"}
    two = {"id": "b", "rule_id": "R2", "score": 50, "last_time": now, "event_keys": ["e2"], "source": "rule"}
    repeat = {"id": "c", "rule_id": "R1", "score": 50, "last_time": now, "event_keys": ["e3"], "source": "rule"}
    assert risk.combine([one])["score"] == 50
    assert risk.combine([one, repeat])["score"] == 50          # one rule's burst does not compound with itself
    assert risk.combine([one, two])["score"] == 75             # two independent signals: 1 - 0.5 * 0.5
    same_event = dict(two, event_keys=["e1"])
    assert risk.combine([one, same_event])["score"] == 50      # same evidence: corroboration, not new evidence


# ----------------------------------------------------------------- state manager
def test_state_windows_are_bounded_and_expire():
    from logplatform.detection.engine.state import ProcessTable, WindowFamily
    family = WindowFamily(ttl=60, max_keys=3, max_per_key=5)
    for key in range(5):
        for t in range(10):
            family.add(key, 1000 + t, {"t": t})
    assert len(family.windows) == 3 and family.evicted == 2 and all(len(w) <= 5 for w in family.windows.values())
    family.add("late", 5000, {})
    family.purge()
    assert list(family.windows) == ["late"]                   # entries older than the TTL are gone
    table = ProcessTable()
    first = table.started({"process.pid": 42, "process.name": "a.exe", "_key": "1"}, 100.0)
    table.ended({"process.pid": 42}, 150.0)
    second = table.started({"process.pid": 42, "process.name": "b.exe", "_key": "2"}, 200.0)
    assert first != second
    assert table.resolve(None, 42, 120.0) == first and table.resolve(None, 42, 250.0) == second   # PID reuse


# ----------------------------------------------------------------- decisions, suppression, learn-only
def test_suppression_covers_exact_activity_only(client):
    b = Builder()
    b.add(4720, "Security", b.at(0), {"TargetUserName": "svc_backup", "SubjectUserName": "admin"})
    ingest(client, b.events)
    item = next(i for i in detections(client)["items"] if "SEC-4720" in i["rule_ids"])
    origin = {"origin": "http://testserver"}
    assert client.post(f"/api/detections/{item['id']}/verdict", json={"verdict": "false_positive"}).status_code == 200
    # A false-positive verdict alone never whitelists anything.
    b2 = Builder(start=NOW() - timedelta(hours=6))
    b2.add(4720, "Security", b2.at(0), {"TargetUserName": "svc_backup", "SubjectUserName": "admin"})
    ingest(client, b2.events)
    assert sum(1 for i in detections(client)["items"] if "SEC-4720" in i["rule_ids"]) == 2
    assert client.post(f"/api/detections/{item['id']}/suppress", json={"reason": "x"}, headers=origin).status_code == 422
    assert client.post(f"/api/detections/{item['id']}/suppress", json={"reason": "planned backup account"}).status_code == 200
    b3 = Builder(start=NOW() - timedelta(minutes=50))
    same = b3.add(4720, "Security", b3.at(0), {"TargetUserName": "svc_backup", "SubjectUserName": "admin"})      # identical
    other = b3.add(4720, "Security", b3.at(2400), {"TargetUserName": "attacker", "SubjectUserName": "admin"})    # different
    ingest(client, b3.events)

    def holding(event):
        for scope in ("active", "suppressed"):
            for found in detections(client, scope=scope)["items"]:
                detail = client.get(f"/api/detections/{found['id']}").json()
                if event["id"] in detail["events"]:
                    return scope, detail
        return None, None
    scope, detail = holding(same)
    assert scope == "suppressed" and all(s["decision"] == "suppressed" for s in detail["signals"])
    scope, detail = holding(other)
    assert scope == "active"                                 # materially different activity still alerts
    rules = client.get("/api/detections/rules", params={"limit": 1}).json()
    assert any(s["matches"] >= 1 for s in rules["suppressions"])
    counts = client.get("/api/detections/summary", params={"range": "all"}).json()
    assert counts["suppressed"] >= 2                         # counted separately, not as active alerts


def test_deterministic_rules_alert_while_model_learns(client):
    from logplatform.detection.engine.service import service
    assert service().behavior.state["stage"] == "learn"
    b = Builder()
    b.add(1102, "Security", b.at(0), {"SubjectUserName": "x"}, provider="Microsoft-Windows-Eventlog")
    ingest(client, b.events)
    assert detections(client)["total"] >= 1                 # the immature model never blocks rule alerts
    with_behaviour = detections(client, source="behavior")["total"]
    assert with_behaviour == 0                               # ...and raises no behaviour alerts itself


def test_restart_rebuilds_correlation_state_without_reprocessing(state_dir):
    from fastapi.testclient import TestClient
    from logplatform.app import app
    b = Builder()
    for i in range(10):
        b.logon(b.at(i), "restart", "0x0", success=False)
    with TestClient(app) as client:
        ingest(client, b.events)
        assert "COR-001" not in rule_ids(client)
        before = client.get("/api/detections/status").json()["processing"]["processed"]
        assert before == 10
    b2 = Builder()
    b2.logon(b.at(20), "restart", "0xfe")
    with TestClient(app) as client:                       # new process state: replay + checkpoint
        status = client.get("/api/detections/status").json()["processing"]
        assert status["replayed"] >= 10 and status["processed"] == 0
        ingest(client, b2.events)
        assert "COR-001" in rule_ids(client)
        assert client.get("/api/detections/status").json()["processing"]["processed"] == 1   # only the new event


# ----------------------------------------------------------------- behaviour model
def test_behaviour_lifecycle_learning_rules_and_feedback(monkeypatch):
    from logplatform.detection.engine import behavior
    monkeypatch.setenv("GRIFFENDO_BEHAVIOR_MIN_OBSERVATIONS", "300")
    monkeypatch.setenv("GRIFFENDO_BEHAVIOR_MIN_LEARNING_DAYS", "0.05")
    monkeypatch.setenv("GRIFFENDO_BEHAVIOR_MIN_SHADOW_HOURS", "1")
    model = behavior.BehaviorModel()
    start = 1_800_000_000.0

    def proc(t, parent, child, user="alice", cmd="x.exe /a"):
        stamp = __import__("datetime").datetime.fromtimestamp(t, __import__("datetime").timezone.utc).isoformat()
        return {"_key": f"k{t}", "@timestamp": stamp, "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
                "winlog.event_id": 1, "process.name": child, "process.parent.name": parent, "user.name": user,
                "process.command_line": cmd, "_lower": {}}

    t = start
    for i in range(1200):                                  # a stable routine over ~5 hours
        t = start + i * 15
        ev = proc(t, "explorer.exe", ["chrome.exe", "outlook.exe", "code.exe"][i % 3], cmd=f"app.exe /n {i % 7}")
        features = model.features(ev)
        result = model.score(ev, features, privileged=False)
        model.learn(features, t, result)
        if i % 100 == 0:
            model.lifecycle(t)
    assert model.state["stage"] == "shadow"                  # promoted only after enough, stable data
    mean_before = model.state["num"]["cmdline_length"]["mean"]
    rare = proc(t + 10, "winword.exe", "rundll32.exe", user="alice", cmd="rundll32.exe " + "A" * 400)
    features = model.features(rare)
    scored = model.score(rare, features, privileged=False)
    assert scored["R"] >= 0.6 and any(p["new"] for p in scored["parts"] if p["feature"] == "parent_child")
    assert not model.learn(features, t + 10, scored)        # high-risk observation is NOT learned (poisoning guard)
    assert model.state["num"]["cmdline_length"]["mean"] == mean_before
    # Missing features are skipped, never add risk.
    bare = {"_key": "b", "@timestamp": rare["@timestamp"], "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
            "winlog.event_id": 1, "process.name": "chrome.exe", "_lower": {}}
    assert all(p["feature"] != "cmdline_length" for p in model.score(bare, model.features(bare), False)["parts"])
    # Shadow -> active after the shadow period with a low would-be alert rate.
    model.state["shadow"].update(since=t - 7200, would_alert=1, observations=2000)
    model.state["last_time"] = t
    assert model.lifecycle(t)["to"] == "active"
    # Slow updates: one observation moves the mean by lambda * delta.
    stats = {"mean": 10.0, "var": 1.0, "n": 500}
    behavior.BehaviorModel._update_stats(stats, 110.0, 0.01)
    assert stats["mean"] == pytest.approx(11.0)
    # Feedback is narrow and recorded.
    applied = model.feedback("false_positive", scored["parts"])
    assert any("parent_child=winword.exe>rundll32.exe" in change for change in applied["changes"])
    applied = model.feedback("true_positive", [{"feature": "process", "value": "evil.exe"}])
    assert "evil.exe" in model.state["blocked"]["process"]
    # Large drift sends an active model back to shadow.
    model.state["novelty"].update(last_ratio=25.0, last_new=50)
    assert model.lifecycle(t + 3600)["to"] == "shadow"


def test_repeated_false_positives_raise_threshold_and_are_audited():
    from logplatform.detection.engine import behavior
    model = behavior.BehaviorModel()
    base = model.threshold()
    for _ in range(10):
        model.feedback("false_positive", [{"feature": "process", "value": "tool.exe"}])
    assert model.threshold() == pytest.approx(base + 0.05)
