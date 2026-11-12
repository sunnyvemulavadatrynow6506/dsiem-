# Griffendo v5.1 — Detection and Correlation Engine

This round replaces the v4 anomaly engine with a single-host detection and correlation engine, following the Phase 3 specification. It is built on the v4 source (`Griffendo_v4_source.zip`). The v4 report is now `docs/REPORT_v4.md`.

**How this was tested.** All testing used synthetic data: hosts are named `SYNTHETIC-*`, and no real Windows telemetry was available. The Windows build was checked by repacking and inspecting the exe and by running it under Wine on Linux. It has **not** been run on a real Windows machine (see §12). Every performance figure was measured; none is estimated. Raw results are in `docs/perf/`.

## 0. v5.1 update: start-up hang and slow pages (1 November 2026)

You reported that the v5.0 exe stayed at "Starting dashboard..." and that the dashboard address never loaded. You also said other pages took a long time to load. This section covers what caused it, what changed, and how it was retested. Sections 1–12 describe v5.0 and still apply, except where this section says otherwise.

### 0.1 Causes found (all reproduced)

| # | Cause | Effect |
|---|---|---|
| 1 | At start-up, before serving any page, the server rebuilt correlation state from the stored events. With 1M events it replayed 132,903 of them, holding the shared database lock throughout | About 28 s before the dashboard could answer, and longer on a slower disk. The launcher gives up after 30 s |
| 2 | Every start created an index over all events (`idx_events_id`) and then dropped it again | About 2.3 s of wasted work per start at 1M events, and much more on a slow disk |
| 3 | The receiver checked each incoming event's channel against a list it rebuilt from all 1,456 rules **for every event** | Event ingestion was about 5× slower than v4 (the "622 events/s" in §8.2) |
| 4 | The "events waiting for detection" figure, shown on every 3-second poll, counted the backlog row by row | 1–2 s per poll while history was being processed |
| 5 | Every page query waited on one shared database lock. Detection work held it during long reads | A single slow read stalled every page for seconds |
| 6 | Per-rule counts on the Rules page read every stored signal row. Other counts used queries without suitable indexes | Rules page about 9 s on first open at 540,000 signals. Detections summary about 1.2 s |
| 7 | The detection worker processed 2,000-event batches back to back, and pages redrew completely on every change | The dashboard felt stuck while history was collected |

Cause 1 is the most likely reason for the hang you saw: a restart with collected history pushed start-up past the launcher's 30-second limit. Your exact Windows data was not available, so I reproduced this with the same code on synthetic stores of 1M events (§0.3).

### 0.2 Changes

**Start-up and the launcher**
- **The server answers before the engine is ready.** It starts serving as soon as the database is open. The 1,456 rules load in a background thread, and the correlation-state rebuild runs in the detection worker afterwards. The rebuild now reads in short pages and does its work outside the shared lock, giving way to requests in between.
- **Pages don't hang while the engine starts.** Detection pages answer within 2 s with "the detection engine is still starting". The page fills in by itself when the engine is ready.
- **The launcher shows progress.** It reports the start-up phase every 5 s and waits up to 15 minutes instead of 30 s. That longer limit is for the one-time upgrade of a very large v4 store. On error, the console window stays open until Enter is pressed.
- **Local traffic bypasses proxies.** The launcher's health check and the collector's traffic to `127.0.0.1` no longer go through a system or company proxy (`NO_PROXY`).

**Database**
- **Pages read without waiting for writes.** Page reads use a separate read-only connection (`db.read()`); SQLite in WAL mode lets them run alongside the writer. Writes still go through the shared lock.
- **No index churn at start-up.** The index that was built and then dropped on every start is gone.
- **Cheap backlog figure.** The backlog is now `MAX(rowid) - checkpoint` instead of a row count.
- **New indexes.**
  - A covering index on signals by rule, used by the Rules page.
  - `det_detections(updated_at)`, used for the data-version check.
  - `det_detections(decision, det_time, severity_rank)`, used for suppressed counts.
- **Endpoint page.** It reads the host list from the host aggregate instead of scanning detections.

**Detection engine**
- **Ingestion back to v4 speed.** The per-event channel check is cached per rule-set version.
- **The engine gives way to people.** While a page or the collector is being served, and for 300 ms after, the worker waits (up to 2 s at a time) and then processes at most 300 events. Collection and the dashboard come first; detection catches up afterwards.
- **Faster matching.** A test that appears in many rules, such as "channel is Security", is computed once per event and shared. Rule conditions use plain loops. Together these make matching about a third faster (2,042 → 2,730 events/s, matching only).
- **Caching.** Counts are cached by data version. Results younger than 5 s are reused while a backlog is being processed. The cache is cleared when the engine catches up, and after rule switches, verdicts and suppressions.
- **Warm-up.** After start-up, the counts the first pages need (Overview, menu badge, Detections, Endpoint, Rules) are computed in the background.

**Browser**
- **Fewer redraws.** While data changes on every poll, the Overview, Endpoint, Timeline and Events views redraw at most every 10 s, and never twice at once.
- **Progress bar.** A thin bar at the top appears when a request takes longer than 300 ms.
- **Engine status.** The status line says "detection engine starting", "rebuilding correlation state" or "detecting (N queued)".

### 0.3 Retest

**The exe under Wine 9.0, on a store of 1,000,000 events and 155,701 detections** (the same store as §8):

| | v5.0 exe | v5.1 exe |
|---|---|---|
| Dashboard answering, after a cold start (disk cache dropped) | not within the launcher's 30 s: start-up work alone was about 34 s with source on Linux | **3.5 s**, including Wine start-up |
| Detection rules ready, cold start | (see above) | 16.6 s; pages show "engine starting" until then |
| Dashboard answering, warm start | — | 3.3 s; rules ready 3.3 s later |
| Every page API after start-up (steady state, Wine) | Rules 9 s cold, summary 1.2 s, endpoint 0.8 s | 0.01–0.23 s |

**The same exe in headless Chromium**, opening every page on the 1M store right after launch:

| Page | Time until content showed |
|---|---|
| Overview, first load | 7.7 s, including waiting for the rules to load |
| Detections | 2.7 s |
| Detection detail | 0.15 s |
| Rules | 3.8 s |
| Timeline | 0.43 s |
| Endpoint | 0.49 s |
| Events | 0.12 s |
| Overview again | 0.10 s |

There were no JavaScript errors. The first visits fall in the first seconds after start-up, while the correlation-state rebuild is still running. Once it settles, the same pages load in 0.1–0.2 s.

**Fresh store (exe under Wine).** 5,010 synthetic events were ingested in 2.1 s and processed with 0 errors. Brute force (12 failures then success) gave COR-001, High, score 73. Remote logon then account creation gave CHN-005, High. The rule switch off/on worked. The detection count from the summary equals the count from the list (2,324).

**Benchmark, 200,000 synthetic events** (`tools/benchmark_v5.py`; raw results in `docs/perf/v51_baseline_v4_200k.json` and `docs/perf/v51_200k.json`):

| | v4 | v5.1 |
|---|---:|---:|
| Ingestion | 4,195 events/s | **4,042 events/s** (v5.0: about 5× slower) |
| Overview, first / repeat | 858 / 12 ms | **291 / 5 ms** |
| Endpoint | 965 / 988 ms | **179 / 27 ms** |
| Timeline | 511 / 14 ms | **16 / 14 ms** |
| Detections | 39 / 37 ms | 162 / 12 ms |
| Rules | — | 177 / 11 ms |
| Events | 16 / 14 ms | **7 / 6 ms** |
| Memory at end | 147 MB | 209 MB |

Detection still runs at about 1,100 events/s on this 2-CPU machine. It catches up after collection: 226 s after the last of the 200,000 events. Live collection is a few events per second, far below that rate.

**Tests.** 71 automated tests pass, including 4 new ones in `tests/test_v51_startup.py`:
- the dashboard answers while the engine is held back
- detection pages answer with a notice instead of hanging
- the backlog figure is correct
- shared condition tests are correct and remembered per event

All 27 browser UI checks pass. `tools/verify_exe.py` reports 1,514 checks OK and 0 failures. It now also checks that every application module is inside the exe.

### 0.4 Still true

- **Not run on real Windows.** The exe has not been run on real Windows; Wine is not Windows. Windows Event Log collection itself cannot be exercised under Wine.
- **Untested on very large v4 stores.** If you upgrade straight from a v4 store, the one-time summary-table build runs before the dashboard answers. That took about 15 s at 1M events here. The launcher now waits for it and says so. Very large stores on slow disks may take minutes once.
- **Detection lags after first start.** After the first start, detection of backfilled history runs in the background for a while: roughly 15 minutes per million events at this machine's speed. The dashboard stays usable meanwhile.
- **Grouping can vary slightly with arrival order.** How signals group into detections can differ a little between runs, because detections are anchored on event-time buckets. On the 5,010-event smoke test, v5.0 and v5.1 produced 2,358 and 2,322 detections from the same input.

## 1. Summary

| Requirement | Delivered |
|---|---|
| Pipeline from normalised events through state manager, rule matcher, chain correlator and behaviour model, then signal aggregator, risk scorer, decision and analyst feedback | Yes. `src/logplatform/detection/engine/`, see §2 |
| Behaviour model with your formulas (rarity, z-score, S = Σwᵢsᵢ, R = S·context, μ ← (1−λ)μ + λx with λ = 0.01, low-score-only learning, Learn → Shadow → Active → Adapt) | Yes, §4 |
| Inspect and classify all 499 Elastic TOML rules and all 946 Wazuh XML rules | Yes. Every rule is in `docs/rules_inventory.json` and `docs/Griffendo_v5_Rule_Inventory.xlsx`, §3 |
| One source file per rule, in Python, loaded through a central registry | Yes. **1,456 rule files**, indexed in `rules/index.py` |
| Licence, provenance and attribution kept | Yes. Every generated rule file carries its licence, original ID, file and original query |
| Custom rule builder with a safe language that refuses fields Griffendo does not collect | Yes, §5 |
| Per-rule ON/OFF switch; switching on re-evaluates the last 7 days without duplicates | Yes, §6 |
| Detections page replaces Anomalies, with a 9-part detail view and verdicts | Yes, §7 |
| Three-column detections overview | Yes, §7 |
| Endpoint page with host detection information | Yes, §7 |
| Date and time filters (presets and custom) for Event Explorer and Detections | Yes, §7 |
| Before/after performance for Timeline, Overview and Endpoint | Yes, §8 |
| Collection kept separate from detection; 60-second refresh and manual Refresh kept | Yes, §2.6 and §7 |
| Tests and final report | 67 automated tests and 27 UI checks, all passing (§9) |

## 2. Architecture

```
collector ──HTTP──▶ /api/ingest ──▶ events table (SQLite, WAL)          (unchanged v4 collection path)
                                        │  rowid checkpoint
                                        ▼
                     DetectionService worker (background thread, own DB connection)
                                        │
                     normalizer  ──▶  state manager (process tree, logon sessions, windows)
                                        │
             ┌──────────────────────────┼────────────────────────────┐
        rule matcher               chain correlator             behaviour model ◀─▶ model store
   (single, threshold,          (process ancestry,             (rarity, z-score,     (model.db)
    sequence, new terms,         same logon, same user)         lifecycle)
    Wazuh rule tree)
             └──────────────────────────┼────────────────────────────┘
                                        ▼
                         signal aggregator (entity + 30-min event-time bucket)
                                        ▼
                         risk scorer (rule score clamped to its band, noisy-OR, decay)
                                        ▼
                         decision: alert / suppress / learn-only (shadow)
                                        ▼
                         det_detections ◀── analyst feedback (status, verdict, suppression)
```

### 2.1 Folder structure

```
src/logplatform/detection/
  engine/
    schema.py        sources Griffendo collects and the normalised fields each one produces
    normalizer.py    raw event → ECS-style fields (Sysmon, Security, System, PowerShell, generic)
    conditions.py    the condition language: validation, compilation, explanation, ReDoS guard
    state.py         bounded windows, process table (PID-reuse safe), logon table
    registry.py      Rule objects, validation, index by (channel, event ID)
    matcher.py       single / threshold / sequence / new-terms matching; Wazuh rule tree
    chain.py         chain correlator (process ancestry, same logon, same user)
    behavior.py      self-paced behaviour model
    model_store.py   persistent model and first-seen term store (model.db)
    aggregator.py    groups signals into detections
    risk.py          scores, severity bands, noisy-OR combination, decay
    decision.py      suppression fingerprints, learn-only / shadow decision
    feedback.py      verdicts and statuses
    store.py         detection tables
    service.py       worker, re-evaluation jobs, rule switches, custom rules, feedback
    queries.py       read side for the API (cached by detection data version)
  rules/
    index.py                     generated list of every rule module (the central registry input)
    windows/<source>/rule_*.py   translated Elastic, Wazuh and catalog rules (one rule per file)
    correlation/rule_*.py        CHN-001…CHN-005, COR-001
    behavior/rule_*.py           BEH-PROCESS, BEH-LOGON, BEH-PERSISTENCE, BEH-VOLUME
    custom/                      custom rules are stored in the state database, not here
src/logplatform/detection_api.py   REST API for detections, rules, model, endpoint, timeline
tools/rules_import/                Elastic and Wazuh translators and the generator
```

Rule files per folder:

| Folder | Files |
|---|---:|
| windows/application | 544 |
| windows/sysmon | 360 |
| windows/security | 273 |
| windows/defender | 128 |
| windows/system | 77 |
| windows/powershell | 30 |
| windows/other | 19 |
| windows/firewall | 11 |
| windows/taskscheduler | 3 |
| windows/wmi | 1 |
| correlation | 6 |
| behavior | 4 |
| **Total** | **1,456** |

By origin, the 1,456 files are 382 Elastic, 930 Wazuh, 134 from the Griffendo catalog and 10 written for Griffendo. The `windows/application` folder is large because Wazuh has many Application-channel rules.

Each file contains a header docstring (name, origin, licence and attribution) and one `RULE = {...}` dictionary. A test checks that each file holds exactly one rule, that every file is indexed, and that no rule logic lives in the engine. Loading all 1,456 rules takes about 0.5 s on a warm start.

### 2.2 Normalisation

Events are mapped to ECS-style names (`process.executable`, `process.parent.name`, `user.name`, `winlog.logon.type`, `registry.path`, `destination.ip`, and so on), because that is what the Elastic rules use. Raw EventData is always available as `winlog.event_data.<Name>`, case-insensitive. The Wazuh rules use this form.

Field handling:
- A field that an event does not have is **absent**. Placeholders such as `-` or `n/a` also count as absent.
- A condition on an absent field is false.
- Fields that only EDR products produce (`process.Ext.*`, code signature, thread data) are never invented. A test checks this.

Command lines are split the way Windows `CommandLineToArgvW` does.

### 2.3 Matching

The rule matcher supports four kinds of rule:
- **single event**
- **threshold**: count, optionally grouped by fields, within a window
- **sequence**: EQL `sequence` with `by`, `maxspan`, `until` and `runs`
- **new terms**: first time a value is seen in a history window

Sequences and thresholds work even when events arrive out of order, and they consume the events they used, so one burst does not fire repeatedly. New-terms rules only alert once Griffendo's stored history covers the rule's look-back window. Until then they learn without alerting.

Wazuh rules run as Wazuh does, as a rule tree:
- A child is tried only after its parent matches (`if_sid`).
- Frequency children are tried first, then the rest in file order. The first matching child wins.
- The deepest match is the result, and it alerts if its level is 3 or higher.
- `if_matched_sid` with `frequency`, `timeframe` and `same_field` is supported, as is `if_fts` (first time seen).

### 2.4 Chain correlator

Chain rules link events through the state manager rather than by time alone.

| Rule | Chain | Severity |
|---|---|---|
| CHN-001 | Office application → script interpreter → scheduled task created | High |
| CHN-002 | Office application → script interpreter → network connection and scheduled task | Critical |
| CHN-003 | New service installed → its program starts | High |
| CHN-004 | Script interpreter → autostart registry value set | High |
| CHN-005 | Remote logon → administrative changes in the same logon session | High |
| COR-001 | Repeated failed logons → successful logon (sequence) | High |

The relations are child-of, descendant-of, same logon session, same user and field-equals. The process table identifies a process by its Sysmon ProcessGuid, or by PID plus start time, so a reused PID is never confused with an earlier process.

Bounds:
- Windows, process table and logon table all have size limits and lifetimes (environment variables in the README).
- The search tries at most 40 candidates per link.
- A test checks that a chain with missing process identifiers does not match on time alone.

### 2.5 Signals, risk and decisions

**Signals.** A rule match produces a signal. Its ID is a hash of the rule, the rule revision and the matched events. Signals are stored with `INSERT OR IGNORE`, so reprocessing never creates duplicates.

**Grouping into detections.** The aggregator groups signals by entity and by a fixed 30-minute slice of event time.
- The entity is the logon session, then the user name, then the process. System accounts are excluded.
- A signal with no entity joins the detection that already contains its event, or forms its own detection.
- Several rules matching the same event therefore give **one** detection with several signals.
- Unrelated events are never merged just because they happened close together. A test checks this.

**Risk score (0–100).**
- Each rule's score is its risk score, clamped to the band of its severity.
- The detection's score combines its signals with a noisy-OR: R = 1 − Π(1 − wᵢ·rᵢ). Behaviour signals have weight 0.6.
- A signal's weight halves every 15 minutes of age within the detection.
- Signals that share the same evidence count once.
- Severity bands are Critical ≥ 90, High ≥ 70, Medium ≥ 40 and Low ≥ 20 (configurable).
- Wazuh levels map to severity as follows: 3 → Informational, 4–6 → Low, 7–9 → Medium, 10–12 → High, 13–15 → Critical.

**Decision.**
- **Alert** is the normal outcome.
- **Suppress** applies when an analyst suppression matches the exact activity fingerprint (rule plus key fields such as user, process path, parent, command line and destination). Suppressed detections are kept and can be listed.
- **Learn-only** applies to behaviour signals while the model is in the Learn stage. In Shadow, behaviour signals are recorded but do not count as active alerts.

**Feedback.** Analysts can set a status (New, Investigating or Resolved) and a verdict (true positive, false positive, benign, or needs investigation), with a comment. Both are stored with a history and survive restarts. A false-positive verdict on a behaviour detection also narrows the model (§4).

### 2.6 Collection and processing are separate

Ingestion only stores events, as in v4, and wakes the detection worker. The worker reads new rows after a checkpoint in its own thread with its own database connection. A slow rule therefore never slows collection.

On start, the worker replays the longest correlation window (plus 24 hours of process and logon events) to rebuild its in-memory state. Signals produced during the replay are not stored a second time.

The UI refresh paths work as follows:
- `/api/live` reports `detections_seq` and the detection backlog.
- The Detections view refreshes every 60 s, keeping scroll position and selection.
- The manual Refresh button triggers a collection pass, waits up to 10 s for detection processing to catch up, and reports what happened.

### 2.7 Overview, Hosts and Events speed-up

The Overview, Endpoint and Event explorer used to scan the whole events table. They now read small aggregate tables kept up to date by SQLite triggers: `agg_host`, `agg_event_id`, `agg_process` and `agg_channel_hour`. The aggregates are built once on first start for an existing database (flag `aggregates_v5`). The effect is measured in §8.

## 3. Rule inventory

Every supplied rule was parsed and classified. The full lists are in `docs/Griffendo_v5_Rule_Inventory.xlsx`, which has these sheets:
- Summary
- Elastic rules
- Wazuh rules
- Griffendo rules
- Excluded (with reasons)
- Field availability
- Licences

The same data is in `docs/rules_inventory.json`.

| Source | Inspected | Fully supported | Requires optional source | Partially supported | Unsupported (excluded) | Rule files |
|---|---:|---:|---:|---:|---:|---:|
| Elastic (`windows.zip`, TOML) | 499 | 100 | 249 | 33 | 117 | 382 |
| Wazuh (`New folder.zip`, XML) | 946 | 787 | 142 | 1 | 16 | 930 |
| Griffendo catalog (from v4) | 134 | 124 | 10 | 0 | 0 | 134 |
| Griffendo correlation and behaviour | 10 | 8 | 2 | 0 | 0 | 10 |
| **Total** | **1,589** | **1,019** | **403** | **34** | **133** | **1,456** |

What the statuses mean:
- **Fully supported.** Everything the rule needs is in the Windows logs Griffendo collects by default.
- **Requires optional source.** The rule is translated and loaded, but it only fires once an optional log is enabled. Most of these rules need Sysmon. Others need PowerShell Script Block Logging, Defender, the Firewall log, Task Scheduler, or extra audit policy (for example process command lines in 4688, or object access auditing). The rule detail and the Endpoint page show which sources are missing.
- **Partially supported.** The rule is loaded, but part of its logic could not be kept, so it may be broader or narrower than the original. Each rule records exactly what changed under "Local modifications". Typical causes are fields only EDR products produce inside one branch of an `or`, and EQL categories with no exact Windows event equivalent.
- **Unsupported.** The rule is excluded with a reason and has no rule file.

### 3.1 Excluded rules

**Elastic (117):**
- **65** need Elastic Defend, Endgame, SentinelOne, Microsoft 365 Defender or the Elastic alert index. The rule names no Windows event log data source at all.
- **27** are ES|QL rules over Windows logs. Their pipeline logic (`STATS`, `EVAL`, `KEEP`, …) is not translated yet. These are marked **OUTSTANDING** in the inventory: they could be ported, but were not done in this round.
- **10** are ES|QL rules over non-Windows data (cloud, network or other platforms).
- **10** could not be translated. These are mostly EQL comparisons between computed values, such as `substring(user.name, …) == host.name`, plus one KQL query the parser does not accept.
- **4** need a field that none of the Windows events in the rule's scope contain: `message`, PowerShell script-block entropy (2 rules), and `process.name` on a source that has no process.
- **1** has a threshold cardinality condition, which is not translated.

**Wazuh (16):**
- **14** test the rendered event message. Windows builds that text from the provider's resources, and Griffendo does not collect it.
- **1** matches on the full Wazuh JSON log line.
- **1** (61053) is a top-level rule without the eventchannel decoder. In Wazuh's own rule order it can never be reached behind rule 60000.

### 3.2 Translation notes

- **EQL and KQL.** Both are parsed into the Griffendo condition language. Wildcards, `:` and `like~`, regex, `cidrmatch`, `startsWith`, `endsWith`, `length`, field-to-field comparison, sequences and `runs` are supported. KQL text fields keep Elasticsearch phrase and token behaviour; keyword fields stay exact.
- **Kibana filters.** These are folded into the condition.
- **Host fields.** `host.id`, `host.name`, `winlog.computer_name` and `agent.id` used as sequence join keys are dropped, because there is only one host.
- **EQL `<category> where`.** This becomes a test on the event category derived from the channel and event ID. It is ignored when the rule already tests the event code or action (this is an approximation; see §12).
- **Wazuh OS_Regex and OS_Match.** These are converted to Python regex: case-insensitive, `\w \d \s \p \.`, and `|` alternatives. Empty alternatives produced by line-wrapped patterns are dropped. Without this, rule 60113 matched every event.
- **Positive test events.** For each translated rule, a generator builds a synthetic event that should match it, and the test then runs that event through the real matcher (§9).

### 3.3 Licences and attribution

- **Elastic rules** are under the Elastic License 2.0. Each rule file keeps the licence notice, the original rule ID, the file name and the original query. The rule detail dialog shows them.
- **Wazuh rules** are under GPL-2.0. Each rule file keeps the GPL notice, the attribution to Wazuh, the original rule ID and the file. **Distributing Griffendo outside your organisation with the Wazuh-derived rules may oblige you to release the corresponding source under GPL-2.0.** Get legal advice before distributing it externally. The Wazuh rules are separate files (`WAZ-*`) and can be left out of a build.

## 4. Behaviour model

The behaviour model is `engine/behavior.py`, stored in `model.db` in the state folder. Every feature uses only data Griffendo actually collects. Network bytes and destination reputation are not collected and are not modelled.

**Features.**

| Kind | Features |
|---|---|
| Categorical | parent→child process pair, process name, user+process, user+logon type, user+logon source address, service name (7045/4697), scheduled task (4698), channel+event ID |
| Numeric | command-line length, command-line entropy |
| Rates | events per minute, process starts per minute, failed logons per 5 min, error events per 5 min |
| Time | hour of day per user, for logons and process starts |

**Scoring.** These follow your formulas:
- Rarity: r = −log((count + α)/(N + αK)), normalised so that a never-seen value gives 1.
- Numeric deviation: z = (x − μ)/(σ + ε), and s = min(|z|/z_max, 1) with z_max = 6.
- Event score: S = Σwᵢsᵢ / Σwᵢ, over the features the event actually has. A missing feature adds no risk.
- Risk: R = min(1, S·context). The context multiplier is 1.5 for a privileged logon session (4672 seen), 1.3 for a host marked critical, and 1 otherwise.

**Learning.**
- Running means and variances update as μ ← (1−λ)μ + λx with λ = 0.01.
- Only events that score below 0.5 **and** that no rule flagged at Medium or above update the model. This guards against the baseline being poisoned by attacks.
- Counts decay by 2% per day.

**Lifecycle** (shown on Rules → Behaviour model):

| Stage | Behaviour |
|---|---|
| **Learn** | Builds the baseline. Signals are learn-only and never alert. Moves to Shadow after 5,000 observations, 2 days, stable novelty below 0.05 and variance change below 0.25 |
| **Shadow** | Scores events and records would-be alerts without alerting. Moves to Active after at least 24 h if the would-be alert rate is at most 2 per 1,000 events and the false-positive ratio is at most 0.3 |
| **Active** | Alerts through BEH-PROCESS, BEH-LOGON, BEH-PERSISTENCE and BEH-VOLUME. Scores are capped to each rule's severity band |
| **Adapt** | Entered on moderate drift. Learns faster until stable again. Large drift returns the model to Shadow |

Repeated false-positive verdicts on behaviour detections raise that behaviour's threshold by 0.05. Each change is written to an audit table. **Reset model** returns the model to Learn.

Deterministic rules alert from the first event and are never gated by the model's stage. A test checks this.

## 5. Custom rules

Rules → **Add rule** opens a builder for single-event, threshold and sequence rules.

**Sources.** You pick the channel and event IDs. The field list then offers only fields that those sources produce.

**Conditions.** Each row has a field, an operator and values. The operators are:
- equals, wildcard, contains, starts with, ends with
- regex
- greater or less than
- CIDR
- exists
- equals another field

Rows can be combined with all, any and not.

**Safety.** The rule is stored as validated JSON in the same condition language as the translated rules. It is never Python code, and nothing is executed. Regexes with nested quantifiers are rejected (ReDoS guard), and rules have size and depth limits.

**Refused fields.** If a field is never present in the chosen sources, the builder says so and names the source that does have it. For example: "`registry.path` is never present in Security 4624; it is produced by Sysmon 12/13/14". Fields not collected at all are refused.

**Prefixes.** The prefixes ELA, WAZ, CHN, COR and BEH are reserved for built-in rules.

**Save, edit and delete.** Saving runs the 7-day look-back for the new rule. Editing creates a new revision: detections from the old revision stay in history but stop being active. Deleting keeps history.

## 6. Rule switches

Every rule has an ON/OFF switch on the Rules page. The setting persists across restarts.

**Switching off** hides the rule's detections from every active view (list, counts, overview, badge, timeline, endpoint). The data is kept. A detection that other enabled rules also matched stays active, and its rule history is kept (`signal_rules`).

**Switching on** starts a background job that re-evaluates the last 7 days for that rule only.
- Signal IDs are deterministic, so already-stored signals are not duplicated.
- Sequence, threshold and Wazuh frequency rules are recomputed over the window.
- The rule list shows the job's progress.

Wazuh grouping rules below level 3 cannot be switched off, because their children depend on them. The API refuses the change and explains why.

## 7. User interface

**Navigation.** The menu is Overview, Detections (with a badge), Rules, Event explorer, Processes, Timeline, Endpoint.

**Overview.** A status row shows:
- the latest detection
- the engine state, including backlog
- the behaviour model stage

Below it are **three columns: Critical + High, Medium, and Low + Informational**. Each column shows counts per severity and the most recent detections. Clicking a count opens the Detections page filtered to that severity. The counts come from the same query as the Detections page.

**Detections page.**
- Scope tabs: Active, Suppressed, History (rule switched off or changed), All stored.
- Filters: text search, severity, category, rule name, event ID, status, verdict, rule on/off, and detector (rule matcher, chain correlator, behaviour model), plus the time filter.
- Sorting: newest, oldest, highest risk, severity.
- Paging.
- A 60-second refresh that keeps scroll position and selection.

**Detection detail.** The detail has nine numbered parts, with 5–7 shown together:
1. Summary (severity, score, entity, time span, MITRE)
2. Why it was triggered (each signal and what it matched)
3. Risk score and severity, with the calculation
4. Matched rule conditions, in plain language
5–7. Correlated sequence, chain links and contributing events, oldest first
8. Recommended investigation steps
9. Analyst verdict and status: TP / FP / benign / needs investigation, with comment, history and suppression

**Rules page.** It has four tabs:
- Rules: switch, signal counts, origin, status, and a detail dialog with provenance, licence and the original query.
- Behaviour model.
- Suppressions, which can be revoked.
- Coverage: which optional sources would enable more rules.

**Timeline.** Shows detections, oldest first, with keyset paging so no entry is missed or duplicated while paging.

**Endpoint.** Shows:
- host identity (name, OS, agent, last check-in)
- monitoring status (collector mode, last heartbeat, detection engine state)
- detections on this host in the last 7 days, by severity, and the latest detection time
- recent detections
- event collection per channel: state, events stored, number of rules using it, last success
- optional sources, whether each is available, and how many rules need it

**Time filters.** Detections and Event explorer have:
- presets: All time, last 15 minutes, last hour, last 6 hours, last 24 hours, last 7 days
- a custom range with start and end date and time
- the API also accepts `30d`

A start later than the end is rejected with a message. The range applied is shown, and it is applied in the database query, not in the browser.

## 8. Performance

Both runs used `tools/benchmark_v5.py` with the same synthetic data:
- 1,000,000 events over 7.5 days on one host
- a mix of Security, System, Application and Sysmon events (process, network, registry, file)
- ingested over HTTP in batches of 5,000, as the collector does

The v4 run used the v4 source tree (`/home/claude/v4base`). Both ran on the same 2-CPU Linux container. "Cold" means the first call after ingest and processing; "warm" is the median of the next two calls. A page's time is the total of the API calls it makes when opened.

Raw results: `docs/perf/v5_baseline_v4_1M.json` (before) and `docs/perf/v5_1M.json` (after).

### 8.1 Page loading (1M events)

| Page | v4 cold | v5 cold | v4 warm | v5 warm | Change (cold) |
|---|---:|---:|---:|---:|---|
| **Overview** | 4,847 ms | **2,368 ms** | 12 ms | 148 ms | 2.0× faster cold; warm is slower (see below) |
| **Endpoint** | 5,446 ms | **900 ms** | 5,323 ms | **313 ms** | 6× faster cold, 17× faster warm |
| **Timeline** | 2,868 ms | **24 ms** | 14 ms | 20 ms | 119× faster cold |
| Detections (was Anomalies) | 1,156 ms | 754 ms | 72 ms | 165 ms | 1.5× faster cold |
| Rules | — | 2,125 ms | — | 153 ms | new page (rule list with signal counts) |
| Event explorer | 21 ms | 7 ms | 17 ms | 6 ms | |
| Event explorer, last hour | — | 8 ms | — | 6 ms | new time filter, applied in SQL |

These pages do different amounts of work in each version. For example, the v5 Overview also computes the three detection columns, which v4 did not have. The comparison is the time a user waits for that page, not a like-for-like query.

**Why it is faster.**
- Overview, Endpoint and Hosts read the trigger-maintained aggregate tables instead of scanning 1M events.
- The Timeline reads detections through a keyset index instead of joining every flagged event.
- Event totals come from the aggregates.

**Warm Overview and Detections are slower than v4.** They are 148 ms and 165 ms, against 12 ms and 72 ms. v4 cached the whole response. v5 re-runs the severity and column counts whenever new detections arrive, so they always match the Detections page. Both stay well under the 60-second refresh.

### 8.2 Ingestion and detection throughput (measured; a regression)

| | v4 | v5 |
|---|---:|---:|
| Ingest (events stored per second while sending) | 2,505 ev/s | **622 ev/s** |
| Detection engine throughput (worker alone) | — | 892 ev/s |
| Detection backlog left when ingest finished | — | 754 s |
| Memory (RSS) at end | 209 MB | 388 MB |
| Detection errors | — | 0 |

**Ingestion is about 4× slower than v4 on this 2-CPU machine.** Two things cause it:
1. Each stored event updates four aggregate tables through triggers.
2. The detection worker runs in the same process as ingestion. Python runs only one thread at a time, so the worker's matching (1,456 rules, state tracking, behaviour scoring) competes with ingestion for CPU.

The two stay separate in the sense that collection never waits for detection: events are stored first and the worker catches up afterwards. With 1M events arriving as fast as possible, the worker finished 754 s after the last batch.

In normal live operation the collector delivers a few events per second, far below either limit. The cost shows on **first start**, when the collector backfills up to 14 days of history. Storing that history, and detecting on it, takes several times longer than in v4.

This was measured and not fixed in this round. Possible fixes:
- running the worker in a separate process
- pausing the worker during a large backfill
- deferring aggregate updates during backfill

The synthetic mix is deliberately busy. It produced 540,990 signals and 155,701 detections, 101,625 of them Informational, mostly from Wazuh level-3 rules. Real data will differ.

### 8.3 Other measurements

- Rule loading: about 0.5 s for 1,456 rules, warm start.
- Restart: correlation state is rebuilt by replaying the longest window. A test checks that no signal is stored twice.
- Exe under Wine: 5,010 events were processed in about 4 s by the worker; ingest took 6.5 s. This is a functional check only, not a benchmark.

## 9. Tests

`python -m pytest tests` runs **67 tests, all passing**. All use synthetic events.

| File | Tests | Covers |
|---|---:|---|
| `test_v5_engine.py` | 21 | normaliser and command-line splitting; condition language; no duplicates on reprocessing; failed-logons → success; the four chains; safe handling of missing process IDs; out-of-order arrival; Wazuh frequency; one detection for several rules on one event; no merging by time alone; risk scale and noisy-OR; bounded state; exact-activity suppression; deterministic rules alert while the model learns; restart rebuilds state without reprocessing; behaviour lifecycle and feedback; FP threshold audit |
| `test_v5_api.py` | 13 | switch off/on everywhere plus catch-up; persistence; protected rules; custom rule validation, create/edit/delete, threshold and sequence; time filters for events and detections; overview and endpoint; timeline paging; verdict persistence; detail sections; honest manual refresh |
| `test_v5_rules.py` | 9 | one rule per file and index; every rule folder is a real package (needed by the exe); inventory covers all 499 + 946 rules; excluded rules not loaded; licence and provenance per rule; no invented EDR fields; generated positive events fire; Wazuh rule tree; stable IDs |
| `test_collector.py`, `test_timeline_collection.py` | 24 | v3/v4 collection, persistence and timeline behaviour, kept and ported |

Three v4 test files tested the anomaly engine that was replaced. They were removed: `test_anomalies.py`, `test_rules_counts.py` and `test_v4_behaviour.py`.

**Positive-event results** (`docs/perf/v5_rule_witness_results.json`):
- **Elastic, catalog and Griffendo rules:** 516 fired on their generated event. One had no generable event (ELA-642CE354-71C1). None missed.
- **Wazuh rules:** 806 fired through the full rule tree.
  - 15 were taken by an earlier sibling, which is correct Wazuh behaviour, as Wazuh stops at the first matching sibling.
  - 2 had no generable event (60134, 60135).
  - None missed.

Rules using `if_group`, `if_fts` or below level 3 are covered by the tree tests rather than individually.

**UI acceptance** (`tools/ui_acceptance_v5.js`, Playwright with headless Chromium, against the synthetic demo): **27 of 27 checks pass** on the final build. On one earlier run, "column counts equal the shared summary" failed. The demo adds live events every 2 seconds, so the page and the check can read the counts a moment apart. The next run passed. This is a timing issue in the check, not a count mismatch. They cover:
- the overview columns matching the API
- severity drill-down
- time presets and the custom-range error
- the detail sections
- saving a verdict
- the chain detail
- the 60 s note
- rule switch off and on
- rule detail provenance
- the builder refusing `registry.path` for Security 4624
- saving a custom rule
- model stage
- timeline order
- endpoint content
- the Event explorer time filter
- no horizontal scroll at 1024 and 390 px
- no JavaScript errors

Screenshots are delivered with this report.

## 10. Files

**New:**
- `src/logplatform/detection/` (engine: 16 modules; rules: 1,456 rule files, `index.py`, package files)
- `src/logplatform/detection_api.py`
- `web/detections.js`
- `tools/rules_import/` (`eql.py`, `kql.py`, `availability.py`, `elastic.py`, `wazuh.py`, `griffendo_rules.py`, `generate.py`)
- `tools/build_inventory_xlsx.py`, `tools/benchmark_v5.py`, `tools/ui_acceptance_v5.js`
- `tests/test_v5_engine.py`, `tests/test_v5_api.py`, `tests/test_v5_rules.py`, `tests/v5_events.py`
- `docs/rules_inventory.json`, `docs/Griffendo_v5_Rule_Inventory.xlsx`, `docs/perf/v5_*.json`, this report

**Modified:**

| File | Change |
|---|---|
| `src/logplatform/app.py` | version 0.5.0; starts the detection service; ingest wakes the worker; events time filter and fast totals; overview and hosts from aggregates; `/api/live` and `/api/refresh` report detection state; legacy `/api/anomalies` kept read-only |
| `src/logplatform/db.py` | aggregate tables and triggers; one-time build; accurate inserted counts |
| `src/logplatform/parser.py` | keeps System fields: keywords, task, opcode, level, process and thread ID, user ID |
| `src/logplatform/anomalies.py` | rule channels supplied by the new registry; faster channel aggregates |
| `src/logplatform/state.py` | verdict and suppression tables |
| `src/logplatform/timeline.py` | flags come from active detections |
| `web/index.html`, `web/app.js`, `web/styles.css` | Detections, Rules, Timeline, Endpoint and Overview sections; time filters; old anomaly code removed |
| `tools/demo_server.py` | synthetic brute-force, Office → PowerShell → scheduled task, and remote logon → account creation data |
| `tools/repack_exe.py`, `tools/verify_exe.py` | include the detection packages and `detections.js` |
| `tests/conftest.py`, `tests/test_timeline_collection.py` | drain the detection worker in tests |
| `README.md` | new environment variables |

**Removed:** `tests/test_anomalies.py`, `tests/test_rules_counts.py`, `tests/test_v4_behaviour.py`.

## 11. Build

`Griffendo.exe` was rebuilt with `tools/repack_exe.py` from the original exe. It keeps the original PyInstaller bootloader and runtime and replaces only Griffendo's own modules and web files. It adds the detection packages.

| | |
|---|---|
| File | `Griffendo.exe`, 19,776,406 bytes |
| SHA-256 | `5a40d1ea7e31bfb28939f714a50a6343922807b09a43d79a8df520e01d020153` |
| Built from | original exe SHA-256 `98578d796a093eda2b8d70ae4237ef6d4f174a9799214c65ec65dd571f97ae42` |
| `tools/verify_exe.py` | 1,512 checks OK, 0 failures |

`verify_exe.py` checks the following:
- every replaced module, compared as compiled code with the current source
- every web file, byte for byte
- every untouched entry, byte for byte against the original
- that every package folder is a real package in the exe
- that all 1,456 indexed rule modules are present

**Wine run (Linux, Wine 9.0).** The exe was started with `--no-browser --no-collect`, and synthetic events were sent to it over HTTP. The results:
- It reported version 0.5.0.
- It loaded all 1,456 rules with 0 load errors. The Rules page lists 1,364: the other 92 are Wazuh grouping rules below level 3 that never alert.
- The detection worker processed 5,010 events with 0 errors.
- Brute force (12 failures then success) gave one COR-001 detection, High, score 73.
- Remote logon followed by account creation in the same session gave a CHN-005 detection, High.
- The Detections, detail, Rules, rule switch off/on with look-back, Endpoint, Timeline, Events time filter and Overview endpoints all answered correctly.

**A bug found by this run, and fixed.** The first v5 exe loaded only 10 rules. The `rules/windows` folder had no `__init__.py`. That works when running from source (namespace package) but not in a PyInstaller exe. The fix:
- The file was added.
- The generator now always writes it.
- A test checks that every rule folder is a regular package.
- `verify_exe.py` checks package entries and that every rule module is present.

Windows event collection itself (the Windows Event Log API) cannot be exercised under Wine and was not tested here.

## 12. Limitations (read these)

1. **Not tested on real Windows.** Everything was verified with synthetic events on Linux, and the exe under Wine. Real event formats, especially Sysmon and audit-policy-dependent fields, may differ in ways the synthetic data does not show.
2. **Wazuh GPL-2.0 distribution caveat.** See §3.3.
3. **27 ES|QL Elastic rules over Windows logs are outstanding** (not ported), plus 10 not translated because of EQL computed-value comparisons.
4. **Elastic categories are approximate.** EQL categories such as `process`, `registry` and `network` are mapped to channels and event IDs. An event-category test is ignored when the rule also tests the event code. A few rules may therefore be slightly broader or narrower than in Elastic. These rules are marked "partially supported" with the exact change.
5. **The behaviour model can mature from backfilled history.** On first start the collector backfills up to 14 days. The model learns from that history, so it can leave Learn sooner than it would on live data alone. Learn-stage signals never alert.
6. **Wazuh sibling precedence.** As in Wazuh, the first matching sibling wins. In tests, 15 rules lost to an earlier sibling. This is expected, but it means some Wazuh rules rarely or never fire on their own.
7. **Interpretation choices.** OS_Regex was converted to Python regex. `frequency`/`timeframe` counting consumes matched events. The `if_fts` key for rule 60119 is taken as target user plus source workstation. These follow Wazuh's documentation but were not compared against a running Wazuh manager.
8. **Rules needing optional sources stay silent** until Sysmon, PowerShell logging or the extra audit policy is enabled. The Endpoint and Coverage views show which.
9. **Message text is not collected,** so rules that match the rendered message cannot work.
10. **Ingestion is about 4× slower than v4** (622 against 2,505 events/s on this machine), and first-start backfill will take longer. See §8.2. It was measured but not fixed in this round.
11. **Wazuh level-3 rules are noisy.** They alert on routine events, such as successful logons, as Wazuh does by default. They appear as Informational detections. Switch them off on the Rules page, or filter by severity, if they are not wanted.
12. **Performance figures** come from a 2-CPU Linux container with synthetic data. Real hardware and real event mixes will differ.
