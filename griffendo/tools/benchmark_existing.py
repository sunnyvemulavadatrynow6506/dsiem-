"""Time the dashboard aggregates against an EXISTING data folder (e.g. one left by tools/benchmark.py).

    python3.12 tools/benchmark_existing.py STATE_DIR --out result.json

"cold" = caches cleared first (what the first request after new data pays);
"warm" = repeated call with unchanged data.  Run it twice to see the effect of
the OS file cache; the first process start after a reboot is slower still.
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
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--out")
    args = parser.parse_args()
    os.environ["GRIFFENDO_STATE_DIR"] = args.state_dir
    from logplatform import anomalies, app, db

    db.initialize()
    anomalies.load_catalog()
    with db.connect() as connection:
        events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        detections = connection.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    targets = {
        "anomaly_summary": anomalies.summary,
        "overview": lambda: anomalies._cached("overview", app._overview),
        "rules": anomalies.rules_with_status,
        "coverage": anomalies.coverage_overview,
    }
    result = {"events": events, "detections": detections, "api": {}}
    for name, function in targets.items():
        cold = []
        for _ in range(args.repeat):
            anomalies.invalidate_cache()
            started = time.perf_counter()
            function()
            cold.append((time.perf_counter() - started) * 1000)
        warm = []
        for _ in range(args.repeat):
            started = time.perf_counter()
            function()
            warm.append((time.perf_counter() - started) * 1000)
        result["api"][name] = {"cold_median_ms": round(statistics.median(cold), 1),
                               "warm_median_ms": round(statistics.median(warm), 1)}
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
