"""Griffendo Detection and Correlation Engine (v5).

Single-host pipeline (see docs/REPORT.md, "Architecture"):

    stored Windows events
        -> engine.normalizer      normalized event (ECS-style field names, raw EventData kept)
        -> engine.state           sliding windows, process / logon context, TTL + size bounds
        -> engine.matcher         deterministic rules (single event, threshold, sequence, new terms, Wazuh tree)
           engine.chain           multi-event chains joined through process lineage / logon session
           engine.behavior        per-host baseline (rarity, deviation, time-of-day) + lifecycle
        -> engine.aggregator      signals grouped per entity and time bucket
        -> engine.risk            score, severity, confidence, explanation
        -> engine.decision        alert / suppress / learn-only
        -> engine.store           signals + detections (SQLite, same database as the events)
    analyst verdicts -> engine.feedback -> engine.model_store

Rules live one per file under detection/rules/ and are loaded through rules/index.py.
"""
