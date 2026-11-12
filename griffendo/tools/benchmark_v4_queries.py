"""Time the v4 dashboard queries against an EXISTING data folder (e.g. one left by tools/benchmark.py).

    python3.12 tools/benchmark_v4_queries.py STATE_DIR [--eval-rule SEC-4624] [--out result.json]

cold = caches cleared first; warm = repeated call, unchanged data.  --eval-rule measures switching a
(disabled) rule on: the first time (all window events evaluated) and again after off/on (nothing missed).
WARNING: --eval-rule writes detections into that data folder; use a copy.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state_dir")
    parser.add_argument("--eval-rule")
    parser.add_argument("--out")
    args = parser.parse_args()
    os.environ["GRIFFENDO_STATE_DIR"] = args.state_dir
    from logplatform import activity, anomalies, app, db, timeline
    from logplatform.settings import utc_now

    db.initialize()
    anomalies.initialize()
    result: dict = {"queries": {}}
    with db.connect() as connection:
        result["events"] = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        result["detections"] = connection.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]

    def timed(name, function, cold=True, repeat=3):
        values = []
        for _ in range(repeat):
            if cold:
                anomalies.invalidate_cache()
            started = time.perf_counter()
            function()
            values.append((time.perf_counter() - started) * 1000)
        result["queries"][name] = round(statistics.median(values), 1)

    timed("summary_cold_ms", anomalies.summary)
    timed("summary_warm_ms", anomalies.summary, cold=False)
    timed("anomaly_list_page_50_ms", lambda: anomalies.list_anomalies({}, 50, 0))
    timed("anomaly_list_high_ms", lambda: anomalies.list_anomalies({"severity": "High"}, 50, 0))
    timed("grouped_cold_ms", lambda: anomalies.grouped_anomalies({}, 50, 0))
    timed("rules_with_status_cold_ms", anomalies.rules_with_status)
    first = timeline.anomaly_page({}, 200)
    timed("timeline_first_page_cold_ms", lambda: timeline.anomaly_page({}, 200))
    timed("timeline_first_page_warm_ms", lambda: timeline.anomaly_page({}, 200), cold=False)
    timed("timeline_next_page_ms", lambda: timeline.anomaly_page({"after": first["newer_cursor"]}, 200), cold=False)
    timed("timeline_newest_page_ms", lambda: timeline.anomaly_page({"position": "end"}, 200), cold=False)
    timed("timeline_live_changes_ms", lambda: timeline.anomaly_page({"changed_since": max(0, first["seq"] - 100)}, 200), cold=False)
    channels = [row["channel"] for row in app._overview()["channels"] if row["channel"]]
    timed("activity_24h_ms", lambda: activity.hourly_activity(channels, tz_offset_minutes=330), cold=False)
    now = utc_now()
    started = time.perf_counter()
    page, keys, pages = timeline.anomaly_page({}, 500, now=now), [], 1
    total = page["total_events"]
    while True:
        keys += [item["key"] for item in page["items"]]
        if not page["has_newer"]:
            break
        page, pages = timeline.anomaly_page({"after": page["newer_cursor"]}, 500, now=now), pages + 1
    result["timeline_full_walk"] = {"entries": len(keys), "unique": len(set(keys)), "total_reported": total,
                                    "pages": pages, "seconds": round(time.perf_counter() - started, 2)}
    if args.eval_rule:
        rule = args.eval_rule
        anomalies.set_rule_enabled(rule, False)
        with db.connect() as connection:
            connection.execute("DELETE FROM anomalies WHERE rule_id = ?", (rule,))   # scratch copy only
        anomalies.invalidate_cache()
        started = time.perf_counter()
        job = anomalies.set_rule_enabled(rule, True)["evaluation"]
        while job["state"] == "running":
            time.sleep(0.2)
            job = anomalies.evaluation_status(rule)
        first_time = {"seconds": round(time.perf_counter() - started, 2), "candidates": job["candidates"],
                      "inserted": job["inserted"], "state": job["state"]}
        anomalies.set_rule_enabled(rule, False)
        started = time.perf_counter()
        again = anomalies.set_rule_enabled(rule, True)["evaluation"]
        result["enable_rule_evaluation"] = {"rule": rule, "first_enable": first_time,
                                            "re_enable": {"seconds": round(time.perf_counter() - started, 2),
                                                          "restored": again["restored"], "inserted": again["inserted"],
                                                          "state": again["state"]}}
        anomalies.set_rule_enabled(rule, False)
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
