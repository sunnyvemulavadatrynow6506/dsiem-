"""Collector tests with PowerShell mocked (real collection needs Windows)."""
from __future__ import annotations

import importlib
import json
import subprocess
from types import SimpleNamespace

import pytest

DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.setenv("WINLOG_CHANNELS", f"{DEFENDER};{SYSMON};Security;Evil'; Remove-Item C:\\")
    from agent import collector as module
    module = importlib.reload(module)
    yield module
    monkeypatch.delenv("WINLOG_CHANNELS")
    importlib.reload(module)


def test_channels_extend_the_original_four_and_reject_injection(collector):
    assert collector.CHANNELS[:4] == ("System", "Security", "Setup", "Application")
    assert collector.CHANNELS[4:] == (DEFENDER, SYSMON)
    assert not any("'" in channel for channel in collector.CHANNELS)


def test_default_channels_unchanged(monkeypatch):
    monkeypatch.delenv("WINLOG_CHANNELS", raising=False)
    from agent import collector
    assert importlib.reload(collector).CHANNELS == ("System", "Security", "Setup", "Application")


def test_launcher_channel_list_comes_from_enabled_rules():
    from logplatform import anomalies
    channels = anomalies.collector_channels()
    assert channels[:4] == ["System", "Security", "Setup", "Application"]
    assert DEFENDER in channels and SYSMON in channels
    assert "Microsoft-Windows-PowerShell/Operational" not in channels   # only disabled rules use it


def test_time_bound_applies_only_to_added_channels(collector, monkeypatch):
    scripts = {}

    def fake_run(command, **kwargs):
        scripts[command[-1].split("-LogName '")[1].split("'")[0]] = command[-1]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"reset": False, "events": []}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    collector.collect_channel("Security", 0, 100, 50)
    collector.collect_channel(DEFENDER, 0, 100, 50)
    assert "timediff" not in scripts["Security"]
    assert "TimeCreated[timediff(@SystemTime) <= 691200000]" in scripts[DEFENDER]
    assert "EventRecordID > $cursor and EventRecordID <= $upper" in scripts[DEFENDER]


def test_watermark_errors_become_channel_states(collector, monkeypatch):
    def fake_capture(channel):
        if channel == SYSMON:
            raise RuntimeError(f'{channel}: There is not an event log on the localhost computer that matches "{channel}".')
        if channel == "Security":
            raise RuntimeError("Security: Attempted to perform an unauthorized operation.")
        if channel == "Setup":
            return 0
        return 42

    monkeypatch.setattr(collector, "capture_channel_watermark", fake_capture)
    connection = collector.connect()
    watermarks = collector.load_snapshot_watermarks(connection)
    assert watermarks[SYSMON] is None and watermarks["System"] == 42
    states = {name: entry["state"] for name, entry in collector.CHANNEL_STATES.items()}
    assert states == {"System": "ok", "Security": "access_denied", "Setup": "empty", "Application": "ok",
                      DEFENDER: "ok", SYSMON: "unavailable"}
    assert collector.CHANNEL_STATES[DEFENDER]["lookback_hours"] == 192
    assert collector.CHANNEL_STATES["System"]["lookback_hours"] is None


def test_collect_and_spool_and_report(collector, monkeypatch):
    def fake_run(command, **kwargs):
        script = command[-1]
        if "-FilterXPath" not in script:
            return SimpleNamespace(returncode=0, stdout='{"record_id": 3}', stderr="")
        channel = script.split("-LogName '")[1].split("'")[0]
        if "else { 0 }" not in script:  # only the first page (cursor 0) returns events
            return SimpleNamespace(returncode=0, stdout=json.dumps({"reset": False, "events": []}), stderr="")
        events = [{"record_id": i, "xml": f"<Event><System><EventID>{i}</EventID></System></Event>"} for i in (1, 2, 3)]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"reset": False, "events": events}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    connection = collector.connect()
    watermarks = collector.load_snapshot_watermarks(connection)
    collected = collector.collect_and_spool(connection, watermarks)
    assert collected == 3 * len(collector.CHANNELS)
    assert collector.CHANNEL_STATES[DEFENDER]["collected"] == 3

    posted = {}

    class Session:
        def post(self, url, json=None, headers=None, verify=None, timeout=None):
            posted.update(url=url, json=json, headers=headers)
            return SimpleNamespace(raise_for_status=lambda: None)

    monkeypatch.setenv("LOGPLATFORM_URL", "http://127.0.0.1:9/api/ingest")
    monkeypatch.setenv("LOGPLATFORM_TOKEN", "synthetic-test-token")
    collector.report_channel_status(Session(), "synthetic-agent")
    assert posted["url"] == "http://127.0.0.1:9/api/collector/status"
    assert {item["channel"] for item in posted["json"]["channels"]} == set(collector.CHANNELS)


def test_main_still_refuses_non_windows(collector, monkeypatch):
    monkeypatch.setattr(collector.sys, "platform", "linux")
    with pytest.raises(SystemExit):
        collector.main()
