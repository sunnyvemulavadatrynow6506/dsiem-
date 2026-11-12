"""Receiver/API benchmark with SYNTHETIC events (no Windows needed).

    python3.12 tools/benchmark.py --src SRC_DIR --events 200000 --batch 2000 --out result.json

Starts the given source tree's receiver in a subprocess (so its memory can be
measured), ingests synthetic events over HTTP exactly as the collector does,
then times the dashboard API calls.  Collector-side read speed (Windows Event
Log API / PowerShell) cannot be measured here and is not part of this script.
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
IDS = [(4624, "Security"), (4634, "Security"), (4688, "Security"), (4672, "Security"), (4625, "Security"),
       (7036, "System"), (7040, "System"), (1000, "Application"), (4698, "Security"), (7045, "System")]
WEIGHTS = [30, 25, 20, 10, 5, 5, 2, 1, 1, 1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_event(i: int, now: datetime, span_days: float, host: str) -> dict:
    event_id, channel = random.choices(IDS, WEIGHTS)[0]
    when = now - timedelta(seconds=random.random() * span_days * 86400)
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    data = (f'<Data Name="SubjectUserName">user{i % 97}</Data><Data Name="TargetUserName">svc{i % 13}</Data>'
            f'<Data Name="NewProcessName">C:\\Windows\\System32\\proc{i % 211}.exe</Data>'
            f'<Data Name="CommandLine">proc{i % 211}.exe /arg {i}</Data><Data Name="IpAddress">10.0.{i % 250}.{i % 200}</Data>'
            f'<Data Name="ProcessId">0x{i % 65535:x}</Data><Data Name="LogonType">{i % 11}</Data>')
    xml = (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>'
           f"<EventID>{event_id}</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>"
           f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>{i}</EventRecordID><Correlation/><Execution ProcessID="788" ThreadID="1234"/>'
           f"<Channel>{channel}</Channel><Computer>{host}</Computer><Security/></System><EventData>{data}</EventData></Event>")
    key = hashlib.sha256(f"{host}|{channel}|{i}|{xml}".encode()).hexdigest()
    return {"id": key, "channel": channel, "record_id": i, "xml": xml}


def request(base: str, path: str, payload=None, method=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, method=method or ("POST" if data else "GET"),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=600) as response:
        body = response.read()
    return time.perf_counter() - start, len(body), json.loads(body)


def rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return float("nan")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--batch", type=int, default=2000)
    parser.add_argument("--days", type=float, default=7.5)
    parser.add_argument("--hosts", type=int, default=3)
    parser.add_argument("--label", default="")
    parser.add_argument("--out")
    args = parser.parse_args()
    random.seed(7)
    port = free_port()
    state = tempfile.mkdtemp(prefix="griffendo-bench-")
    env = dict(os.environ, LOGPLATFORM_TOKEN=TOKEN, GRIFFENDO_STATE_DIR=state, PYTHONPATH=args.src,
               LOGPLATFORM_MAX_INGEST_EVENTS=str(max(args.batch, 2000)), LOGPLATFORM_MAX_INGEST_BYTES=str(256_000_000))
    server = subprocess.Popen([sys.executable, "-c",
                               f"import uvicorn; from logplatform.app import app; uvicorn.run(app, host='127.0.0.1', port={port}, log_level='warning')"],
                              env=env)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(200):
            try:
                request(base, "/api/health")
                break
            except OSError:
                time.sleep(0.1)
        now = datetime.now(timezone.utc)
        rss_start = rss_mb(server.pid)
        ingest_time = 0.0
        payload_bytes = 0
        sent = 0
        first_batch = None
        while sent < args.events:
            size = min(args.batch, args.events - sent)
            host = f"SYNTHETIC-BENCH-{sent // size % args.hosts:02d}"
            batch = {"agent_id": f"synthetic-{host}", "hostname": host, "os_name": "Windows",
                     "events": [make_event(sent + j + 1, now, args.days, host) for j in range(size)]}
            body = json.dumps(batch)
            payload_bytes += len(body)
            seconds, _, ack = request(base, "/api/ingest", batch)
            if first_batch is None:
                first_batch = seconds
            assert ack["accepted"] == size, ack
            ingest_time += seconds
            sent += size
        result = {"label": args.label, "src": args.src, "events": args.events, "batch": args.batch,
                  "ingest_seconds": round(ingest_time, 2), "ingest_events_per_sec": round(args.events / ingest_time),
                  "first_batch_seconds": round(first_batch, 3), "payload_mb": round(payload_bytes / 1e6, 1),
                  "rss_mb_start": round(rss_start, 1), "rss_mb_after_ingest": round(rss_mb(server.pid), 1), "api": {}}
        since = (now - timedelta(days=7)).isoformat()
        calls = {
            "overview": "/api/overview",
            "events_page1": "/api/events?limit=50",
            "events_filtered": "/api/events?limit=50&channel=Security&event_id=4625",
            "timeline_legacy_100": "/api/timeline?limit=100",
            "anomaly_summary": "/api/anomalies/summary",
            "anomalies_page": "/api/anomalies?limit=50",
            "timeline_page_200": "/api/timeline/page?limit=200",
            "timeline_page_filtered": "/api/timeline/page?limit=200&event_id=4625",
            "rules": "/api/rules",
            "live": "/api/live",
            # v4 endpoints (absent in older versions -> recorded as errors)
            "overview_with_24h_graph": "/api/overview?tz_offset=330",
            "anomaly_timeline_first_200": "/api/timeline/anomalies?limit=200",
            "anomaly_timeline_newest_200": "/api/timeline/anomalies?limit=200&position=end",
            "anomaly_timeline_critical": "/api/timeline/anomalies?limit=200&severity=Critical,High",
        }
        for name, path in calls.items():
            timings = []
            size = None
            try:
                for _ in range(3):
                    seconds, size, _ = request(base, path)
                    timings.append(seconds)
                result["api"][name] = {"first_ms": round(timings[0] * 1000, 1), "median_ms": round(sorted(timings)[1] * 1000, 1),
                                       "bytes": size}
            except Exception as error:  # endpoint absent in older versions
                result["api"][name] = {"error": str(error)[:80]}
        # Deep timeline paging: walk the whole 7-day window and check completeness/duplicates.
        try:
            seen, cursor, pages, walk_start = set(), None, 0, time.perf_counter()
            while True:
                query = {"limit": 500}
                if cursor:
                    query["cursor"] = cursor
                _, _, page = request(base, "/api/timeline/page?" + urllib.parse.urlencode(query))
                pages += 1
                for item in page["items"]:
                    assert item["id"] not in seen, "duplicate across pages"
                    seen.add(item["id"])
                cursor = page.get("next_cursor")
                if not cursor:
                    break
            result["timeline_full_walk"] = {"pages": pages, "events": len(seen), "seconds": round(time.perf_counter() - walk_start, 2),
                                            "window_total_reported": page.get("total")}
        except Exception as error:
            result["timeline_full_walk"] = {"error": str(error)[:120]}
        # v4: walk the whole anomaly timeline (oldest first) and check completeness/duplicates.
        try:
            seen, after, pages, walk_start = set(), None, 0, time.perf_counter()
            _, _, first = request(base, "/api/timeline/anomalies?limit=500")
            page = first
            while True:
                pages += 1
                for item in page["items"]:
                    assert item["key"] not in seen, "duplicate across pages"
                    seen.add(item["key"])
                if not page.get("has_newer"):
                    break
                _, _, page = request(base, "/api/timeline/anomalies?" + urllib.parse.urlencode({"limit": 500, "after": page["newer_cursor"]}))
            result["anomaly_timeline_full_walk"] = {"pages": pages, "events": len(seen), "seconds": round(time.perf_counter() - walk_start, 2),
                                                    "total_reported": first.get("total_events")}
        except Exception as error:
            result["anomaly_timeline_full_walk"] = {"error": str(error)[:120]}
        result["rss_mb_end"] = round(rss_mb(server.pid), 1)
        text = json.dumps(result, indent=2)
        print(text)
        if args.out:
            with open(args.out, "w") as handle:
                handle.write(text)
        return 0
    finally:
        server.terminate()
        server.wait(timeout=30)


if __name__ == "__main__":
    raise SystemExit(main())
