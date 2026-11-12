"""Page-load benchmark, v4 vs v5, with SYNTHETIC events (no Windows needed).

    python3.12 tools/benchmark_v5.py --src SRC_DIR --version v4|v5 --events 1000000 --out result.json

Starts the given source tree's receiver, ingests synthetic events over HTTP (as the collector
does), waits until v5's background detection engine has processed everything, then times the
API calls each page makes when it opens (cold = first call after ingest, warm = median of the
next two).  The event mix includes Sysmon process / registry / network events and logon
sequences so the correlation engine has real work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

TOKEN = "synthetic-benchmark-token"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
KINDS = [("sec4624", 22), ("sec4634", 18), ("sec4688", 15), ("sec4672", 8), ("sec4625", 5), ("sys7036", 5),
         ("sys7040", 1), ("app1000", 1), ("sec4698", 1), ("sys7045", 1), ("smon1", 14), ("smon3", 4), ("smon13", 3),
         ("smon11", 2)]
PROCS = ["svchost.exe", "chrome.exe", "explorer.exe", "powershell.exe", "cmd.exe", "conhost.exe", "msedge.exe",
         "rundll32.exe", "taskhostw.exe", "OneDrive.exe", "notepad.exe", "winword.exe", "excel.exe", "git.exe",
         "python.exe", "code.exe"] + [f"tool{i}.exe" for i in range(60)]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def xml(eid: int, channel: str, provider: str, stamp: str, record: int, host: str, data: dict, level: int = 0) -> str:
    body = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    keywords = "0x8010000000000000" if eid == 4625 else "0x8020000000000000"
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{eid}</EventID><Version>2</Version>'
            f"<Level>{level}</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
            f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>{record}</EventRecordID><Correlation/>'
            f'<Execution ProcessID="788" ThreadID="1234"/><Channel>{channel}</Channel><Computer>{host}</Computer>'
            f"<Security/></System><EventData>{body}</EventData></Event>")


def make_event(i: int, now: datetime, span_days: float, host: str, sysmon: bool) -> dict:
    kinds = KINDS if sysmon else [k for k in KINDS if not k[0].startswith("smon")]
    kind = random.choices([k for k, _ in kinds], [w for _, w in kinds])[0]
    when = now - timedelta(seconds=random.random() * span_days * 86400)
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    user = f"user{i % 23}"
    proc = PROCS[i % len(PROCS)]
    parent = PROCS[(i // 7) % len(PROCS)]
    sec = "Microsoft-Windows-Security-Auditing"
    if kind.startswith("sec"):
        eid = int(kind[3:])
        data = {"SubjectUserName": user, "SubjectUserSid": f"S-1-5-21-1-2-3-{1000 + i % 23}",
                "SubjectLogonId": f"0x{1000 + i % 500:x}", "TargetUserName": user if eid != 4672 else "-",
                "TargetLogonId": f"0x{1000 + i % 500:x}", "LogonType": str((2, 3, 10, 5)[i % 4]),
                "IpAddress": f"10.0.{i % 250}.{i % 200}", "NewProcessName": f"C:\\Windows\\System32\\{proc}",
                "ParentProcessName": f"C:\\Windows\\System32\\{parent}", "NewProcessId": f"0x{i % 65535:x}",
                "ProcessId": f"0x{(i // 3) % 65535:x}", "CommandLine": f"{proc} /arg {i % 5000}"}
        if eid == 4698:
            data["TaskName"] = f"\\Task{i % 40}"
        channel, provider = "Security", sec
    elif kind.startswith("sys"):
        eid = int(kind[3:])
        data = {"param1": f"Service{i % 50}", "param2": "running", "ServiceName": f"Svc{i % 60}",
                "ImagePath": f"C:\\Program Files\\S{i % 60}\\svc.exe"}
        channel, provider = "System", "Service Control Manager"
    elif kind == "app1000":
        eid, channel, provider = 1000, "Application", "Application Error"
        data = {"param1": proc}
    else:
        eid = int(kind[4:])
        channel, provider = SYSMON, "Microsoft-Windows-Sysmon"
        guid = f"{{{i:08x}-0000-0000-0000-000000000000}}"
        data = {"ProcessGuid": guid, "ProcessId": str(i % 60000), "Image": f"C:\\Windows\\System32\\{proc}",
                "User": f"LAB\\{user}"}
        if eid == 1:
            data.update(CommandLine=f"{proc} -x {i % 3000}", ParentImage=f"C:\\Windows\\System32\\{parent}",
                        ParentProcessGuid=f"{{{i // 7:08x}-0000-0000-0000-000000000000}}",
                        ParentProcessId=str((i // 7) % 60000), OriginalFileName=proc, LogonId=f"0x{1000 + i % 500:x}")
        elif eid == 3:
            data.update(DestinationIp=f"93.184.{i % 250}.{i % 200}", DestinationPort="443", Protocol="tcp",
                        Initiated="true", SourceIp="10.0.0.5", SourcePort=str(40000 + i % 20000))
        elif eid == 13:
            data.update(EventType="SetValue", TargetObject=f"HKLM\\SOFTWARE\\Vendor{i % 30}\\Setting{i % 10}",
                        Details="DWORD (0x00000001)")
        elif eid == 11:
            data.update(TargetFilename=f"C:\\Users\\{user}\\AppData\\Local\\Temp\\f{i % 900}.tmp")
    body = xml(eid, channel, provider, stamp, i, host, data)
    key = hashlib.sha256(f"{host}|{channel}|{i}|{body}".encode()).hexdigest()
    return {"id": key, "channel": channel, "record_id": i, "xml": body}


def request(base: str, path: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=900) as response:
        body = response.read()
    return time.perf_counter() - start, len(body), json.loads(body or b"null")


def rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


PAGES = {
    "v4": {
        "overview": ["/api/overview?tz_offset=330", "/api/anomalies/summary"],
        "endpoint": ["/api/hosts", "/api/events?host={host}&limit=200"],
        "timeline": ["/api/timeline/anomalies?limit=200", "/api/timeline/facets"],
        "detections": ["/api/anomalies?limit=100", "/api/rules", "/api/anomalies/summary"],
        "events": ["/api/events?limit=100"],
        "events_last_hour": None,
    },
    "v5": {
        "overview": ["/api/overview?tz_offset=330", "/api/detections/summary?range=7d&recent=4"],
        "endpoint": ["/api/endpoint", "/api/hosts", "/api/events?host={host}&limit=200"],
        "timeline": ["/api/timeline/detections?limit=200&range=7d&position=start"],
        "detections": ["/api/detections?limit=50&scope=active&sort=time_desc&range=7d",
                       "/api/detections/summary?range=7d"],
        "rules": ["/api/detections/rules?limit=100&sort=signals"],
        "events": ["/api/events?limit=100"],
        "events_last_hour": ["/api/events?limit=100&start={hour_ago}&end={now}"],
    },
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--version", choices=["v4", "v5"], required=True)
    parser.add_argument("--events", type=int, default=200000)
    parser.add_argument("--batch", type=int, default=5000)
    parser.add_argument("--days", type=float, default=7.5)
    parser.add_argument("--hosts", type=int, default=1)
    parser.add_argument("--no-sysmon", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--out")
    args = parser.parse_args()
    random.seed(11)
    port = free_port()
    state = args.state or tempfile.mkdtemp(prefix="griffendo-bench5-")
    env = dict(os.environ, LOGPLATFORM_TOKEN=TOKEN, GRIFFENDO_STATE_DIR=state, PYTHONPATH=args.src,
               LOGPLATFORM_MAX_INGEST_EVENTS=str(max(args.batch, 2000)), LOGPLATFORM_MAX_INGEST_BYTES=str(512_000_000),
               LOGPLATFORM_EXTRA_CHANNELS=SYSMON)
    server = subprocess.Popen([sys.executable, "-c", "import uvicorn; from logplatform.app import app; "
                               f"uvicorn.run(app, host='127.0.0.1', port={port}, log_level='warning')"], env=env)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(300):
            try:
                request(base, "/api/health")
                break
            except OSError:
                time.sleep(0.1)
        now = datetime.now(timezone.utc)
        hosts = [f"SYNTHETIC-BENCH-{n:02d}" for n in range(args.hosts)]
        ingest_time, sent = 0.0, 0
        started = time.perf_counter()
        while sent < args.events:
            size = min(args.batch, args.events - sent)
            host = hosts[(sent // size) % len(hosts)]
            batch = {"agent_id": f"synthetic-{host}", "hostname": host, "os_name": "Windows",
                     "events": [make_event(sent + j + 1, now, args.days, host, not args.no_sysmon) for j in range(size)]}
            seconds, _, ack = request(base, "/api/ingest", batch)
            assert ack["accepted"] == size, ack
            ingest_time += seconds
            sent += size
        ingest_wall = time.perf_counter() - started
        result = {"version": args.version, "events": args.events, "ingest_seconds": round(ingest_time, 1),
                  "ingest_events_per_sec": round(args.events / ingest_time), "rss_mb_after_ingest": round(rss_mb(server.pid), 1)}
        if args.version == "v5":
            wait_start = time.perf_counter()
            while True:
                _, _, status = request(base, "/api/detections/status")
                if not status["processing"]["backlog_events"]:
                    break
                time.sleep(1)
            processing_tail = time.perf_counter() - wait_start
            result["detection_backlog_after_ingest_seconds"] = round(processing_tail, 1)
            result["detection_total_seconds"] = round(ingest_wall + processing_tail, 1)
            result["detection_events_per_sec_end_to_end"] = round(args.events / (ingest_wall + processing_tail))
            result["engine"] = {k: status["processing"].get(k) for k in ("processed", "signals", "events_per_second",
                                                                          "errors", "state")}
            result["detections"] = status["summary_counts"]
        result["rss_mb_after_processing"] = round(rss_mb(server.pid), 1)
        stamp = lambda d: urllib.parse.quote(d.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z")
        values = {"host": hosts[0], "hour_ago": stamp(now - timedelta(hours=1)), "now": stamp(now)}
        pages = {}
        for page, paths in PAGES[args.version].items():
            if not paths:
                pages[page] = None
                continue
            runs = []
            for _ in range(3):
                total, sizes = 0.0, 0
                for path in paths:
                    seconds, size, _ = request(base, path.format(**values))
                    total += seconds
                    sizes += size
                runs.append(total)
            pages[page] = {"cold_ms": round(runs[0] * 1000, 1), "warm_ms": round(sorted(runs[1:])[0] * 1000, 1),
                           "bytes": sizes, "calls": [p.split("?")[0] for p in paths]}
        result["pages"] = pages
        result["rss_mb_end"] = round(rss_mb(server.pid), 1)
        text = json.dumps(result, indent=2)
        print(text)
        if args.out:
            with open(args.out, "w") as handle:
                handle.write(text)
        return 0
    finally:
        server.terminate()
        server.wait(timeout=60)


if __name__ == "__main__":
    raise SystemExit(main())
