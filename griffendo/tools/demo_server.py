"""Run the dashboard locally with SYNTHETIC data (UI review on any OS).

    python tools/demo_server.py [port] [--state DIR] [--events N]

Starts the receiver, then runs the real continuous collector against an
in-memory fake Windows log (tests/fakelog.py) that holds a week of synthetic
history and keeps writing a new synthetic event every few seconds, so live
collection, detection and the live UI can be observed.  Hosts are named
SYNTHETIC-*; nothing reads real Windows logs.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", nargs="?", type=int, default=8765)
    parser.add_argument("--state", default=None)
    parser.add_argument("--events", type=int, default=6000)
    parser.add_argument("--live-every", type=float, default=4.0)
    args = parser.parse_args()
    os.environ.setdefault("LOGPLATFORM_TOKEN", "synthetic-demo-token")
    os.environ.setdefault("GRIFFENDO_STATE_DIR", args.state or tempfile.mkdtemp(prefix="griffendo-demo-"))
    os.environ["LOGPLATFORM_URL"] = f"http://127.0.0.1:{args.port}/api/ingest"

    import uvicorn
    from agent.continuous import ContinuousCollector
    from fakelog import FakeLog
    from logplatform.app import app

    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=args.port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)

    random.seed(11)
    log = FakeLog()
    now = datetime.now(timezone.utc)
    sec, sysc = "Security", "System"
    defender = "Microsoft-Windows-Windows Defender/Operational"
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    for channel in ("System", "Security", "Setup", "Application", defender, sysmon,
                    "Microsoft-Windows-WMI-Activity/Operational"):
        log.logs.setdefault(channel, [])
    noise = [(4624, sec), (4634, sec), (4672, sec), (4688, sec), (7036, sysc), (1000, "Application"), (4625, sec)]
    weights = [30, 25, 12, 20, 8, 3, 2]
    times = sorted(now - timedelta(seconds=random.random() * 7.6 * 86400) for _ in range(args.events))
    for when in times:
        event_id, channel = random.choices(noise, weights)[0]
        log.write(channel, event_id, when, data={"TargetUserName": random.choice(["demo", "svc_backup", "administrator"]),
                                                 "IpAddress": random.choice(["10.0.0.5", "198.51.100.23", "-"])},
                  provider="Microsoft-Windows-Security-Auditing" if channel == sec else None)
    notable = [(1102, sec, 30, {"SubjectUserName": "synthetic.admin"}), (7045, sysc, 5, {"ServiceName": "SynthUpdater", "ImagePath": "C:\\ProgramData\\synth\\svc.exe"}),
               (4720, sec, 26, {"TargetUserName": "svc_synth", "SubjectUserName": "synthetic.admin"}),
               (4732, sec, 25, {"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-0-0-0-1009"}),
               (4698, sec, 24, {"TaskName": "\\SynthNightly"}), (4740, sec, 12, {"TargetUserName": "demo"}),
               (1116, defender, 7, {"Threat Name": "Synthetic:Test/EICAR_Sample"}), (5007, defender, 10, {"New Value": "Exclusions\\Paths\\C:\\Synth"}),
               (8, sysmon, 3, {"SourceImage": "C:\\Synth\\loader.exe", "TargetImage": "C:\\Windows\\System32\\notepad.exe"}),
               (6008, sysc, 60, {"param1": "10:14:02"}), (4616, sec, 90, {"ProcessName": "C:\\Windows\\System32\\svchost.exe"})]
    for event_id, channel, hours, data in notable:
        log.write(channel, event_id, now - timedelta(hours=hours), data=data,
                  provider="Microsoft-Windows-Eventlog" if event_id == 1102 else None)
    # v5 correlation examples: a brute-force sequence, an Office -> PowerShell -> schtasks chain (Sysmon), and a
    # remote logon followed by an account change in the same session.
    t0 = now - timedelta(hours=6)
    for i in range(12):
        log.write(sec, 4625, t0 + timedelta(seconds=i * 7), data={"TargetUserName": "finance01", "LogonType": "3",
                                                                   "IpAddress": "203.0.113.50"},
                  provider="Microsoft-Windows-Security-Auditing")
    log.write(sec, 4624, t0 + timedelta(seconds=100), data={"TargetUserName": "finance01", "LogonType": "3",
                                                             "IpAddress": "203.0.113.50", "TargetLogonId": "0x7a11"},
              provider="Microsoft-Windows-Security-Auditing")
    log.write(sec, 4720, t0 + timedelta(seconds=400), data={"SubjectUserName": "finance01", "SubjectLogonId": "0x7a11",
                                                             "TargetUserName": "helpdesk2"},
              provider="Microsoft-Windows-Security-Auditing")
    t1 = now - timedelta(hours=2)
    g = lambda n: "{%08x-5e5e-0000-0000-000000000000}" % n  # noqa: E731
    chain = [(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE /n Invoice.docm", 1, 0,
              r"C:\Windows\explorer.exe"),
             (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", 2, 1,
              r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
             (r"C:\Windows\System32\schtasks.exe", r"schtasks.exe /create /tn OfficeUpdate /tr C:\Users\demo\AppData\upd.exe /sc onlogon",
              3, 2, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    for offset, (image, command, me, parent, parent_image) in enumerate(chain):
        log.write(sysmon, 1, t1 + timedelta(seconds=offset * 6), provider="Microsoft-Windows-Sysmon",
                  data={"ProcessGuid": g(me), "ProcessId": str(4000 + me), "Image": image, "CommandLine": command,
                        "OriginalFileName": image.rsplit("\\", 1)[-1], "ParentProcessGuid": g(parent),
                        "ParentProcessId": str(4000 + parent), "ParentImage": parent_image, "User": "SYNTH\\demo",
                        "LogonId": "0x51ab"})
    for channel in log.logs:   # records were written out of time order above; keep record order = time order
        log.logs[channel].sort(key=lambda r: r["when"])
        for index, record in enumerate(log.logs[channel], start=1):
            record["record_id"] = index
            record["xml"] = record["xml"].split("<EventRecordID>")[0] + f"<EventRecordID>{index}</EventRecordID>" + record["xml"].split("</EventRecordID>")[1]
        log.next_id[channel] = len(log.logs[channel]) + 1

    collector = ContinuousCollector(source=log, hostname="SYNTHETIC-WS01", interval=2.0)
    from agent.continuous import request_collection
    from logplatform.app import set_collect_trigger
    set_collect_trigger(request_collection)     # the Refresh button triggers an immediate pass, as in the launcher
    stop = threading.Event()
    threading.Thread(target=collector.run, args=(stop,), daemon=True).start()

    def writer():
        live = [(4625, sec), (4624, sec), (4688, sec), (7045, sysc), (4720, sec), (7036, sysc)]
        while not stop.is_set():
            time.sleep(args.live_every)
            event_id, channel = random.choices(live, [5, 10, 6, 1, 1, 4])[0]
            log.write(channel, event_id, data={"TargetUserName": "live-demo", "ServiceName": "LiveSynthService"})

    threading.Thread(target=writer, daemon=True).start()
    print(f"Synthetic demo dashboard: http://127.0.0.1:{args.port}/   (state: {os.environ['GRIFFENDO_STATE_DIR']})")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        server.should_exit = True


if __name__ == "__main__":
    main()
