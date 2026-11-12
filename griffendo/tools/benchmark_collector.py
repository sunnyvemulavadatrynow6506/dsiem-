"""Collector pipeline benchmark with a SYNTHETIC in-memory log (no Windows).

    python3.12 tools/benchmark_collector.py --events 100000 --out result.json

Measures the v3 collector's own pipeline (cursoring, spooling to disk, HTTP
delivery, receiver storage and detection) with the Windows read cost replaced
by an in-memory fake.  It therefore shows the pipeline's ceiling, not the
speed of the Windows Event Log API on a given machine.

It also counts how many PowerShell processes the v2 collector would have
started for the same backlog (one per channel per 222-event slice, plus one
watermark query per channel), which is the cost v3's native reader removes.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--live-samples", type=int, default=20)
    parser.add_argument("--out")
    args = parser.parse_args()
    state = tempfile.mkdtemp(prefix="griffendo-collector-bench-")
    os.environ.update(GRIFFENDO_STATE_DIR=state, LOGPLATFORM_TOKEN="synthetic-benchmark-token")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    os.environ["LOGPLATFORM_URL"] = f"http://127.0.0.1:{port}/api/ingest"

    import requests
    import uvicorn
    from agent.continuous import BACKFILL_BATCH, DELIVERY_BATCH, ContinuousCollector
    from fakelog import FakeLog
    from logplatform.app import app

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.02)
    base = f"http://127.0.0.1:{port}"

    log = FakeLog()
    for channel in ("System", "Security", "Setup", "Application"):
        log.logs.setdefault(channel, [])
    now = datetime.now(timezone.utc)
    span = 6.5 * 86400
    for i in range(args.events):
        channel = "Security" if i % 5 else "System"
        log.write(channel, 4624 if channel == "Security" else 7036, now - timedelta(seconds=span * (1 - i / args.events)),
                  data={"TargetUserName": f"user{i % 50}"})

    collector = ContinuousCollector(source=log, hostname="SYNTHETIC-BENCH", folder=state)
    start = time.perf_counter()
    first_visible = None
    while True:
        result = collector.run_once()
        if first_visible is None:
            total = requests.get(base + "/api/timeline/page", params={"limit": 1}).json()["total"]
            if total:
                first_visible = time.perf_counter() - start
        if not (result["live"] or result["backfill"] or result["spool"]):
            break
    backfill_seconds = time.perf_counter() - start
    stored = requests.get(base + "/api/timeline/page", params={"limit": 1}).json()["total"]

    # Live latency: write an event, run passes on the normal 2 s schedule, poll the API until it is visible.
    stop = threading.Event()
    runner = threading.Thread(target=collector.run, args=(stop,), daemon=True)
    runner.start()
    latencies = []
    for n in range(args.live_samples):
        top = requests.get(base + "/api/timeline/page", params={"limit": 1}).json()["top_cursor"]
        written = time.perf_counter()
        log.write("Security", 4720, data={"TargetUserName": f"live{n}"})
        while True:
            items = requests.get(base + "/api/timeline/page", params={"newer_than": top}).json()["items"]
            if any(item["event_id"] == 4720 for item in items):
                latencies.append(time.perf_counter() - written)
                break
            time.sleep(0.05)
        time.sleep(0.3)
    stop.set()
    latencies.sort()
    channels_v2 = 9
    per_slice = 2000 // channels_v2
    v2_launches = sum(-(-len(records) // per_slice) + 1 for records in log.logs.values() if records) + channels_v2
    result = {
        "events_in_log": args.events,
        "events_stored": stored,
        "backfill_seconds": round(backfill_seconds, 2),
        "pipeline_events_per_second": round(stored / backfill_seconds),
        "time_to_first_visible_events_seconds": round(first_visible or 0, 3),
        "live_latency_seconds": {"min": round(latencies[0], 2), "median": round(latencies[len(latencies) // 2], 2),
                                 "p95": round(latencies[int(len(latencies) * 0.95) - 1], 2), "max": round(latencies[-1], 2),
                                 "samples": len(latencies), "poll_interval_seconds": collector.interval},
        "settings": {"backfill_batch": BACKFILL_BATCH, "delivery_batch": DELIVERY_BATCH},
        "v2_powershell_processes_for_same_backlog": v2_launches,
        "v3_powershell_processes_with_native_reader": 0,
        "note": "Windows read cost excluded (in-memory fake log); see docstring.",
    }
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    server.should_exit = True
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
