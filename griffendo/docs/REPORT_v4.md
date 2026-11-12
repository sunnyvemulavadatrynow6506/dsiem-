# Griffendo v4 — rule switches, anomaly timeline, 24-hour graph, refresh

This round implements the "Additional UI, Anomaly Rules, Timeline, Graph, and Refresh Improvements" request on top of v3. The v3 report is `docs/REPORT_v3.md`.

All data used for testing is synthetic: hosts are named `SYNTHETIC-*`, and there is no real Windows telemetry. Every performance figure below was measured; none is estimated. Raw results are in `docs/perf/v4_*.json`.

## 1. Audit: what was already there and what was not

| Area | State found in v3 | Action |
|---|---|---|
| Rule ON/OFF switch per rule, saved before the UI changes, persisted across restarts, errors shown | Working | Kept unchanged |
| Disabling a rule | Stopped new detections, but its existing detections still counted in the active list, severity cards, badge and widgets | **Corrected** — now hidden from all active views; data kept |
| Enabling a rule | Only new events; history needed a manual "Rescan" | **Corrected** — automatic, targeted 7-day re-evaluation for that rule |
| Editing / deleting custom rules | History kept, but old detections of an edited rule stayed "active" even when they no longer matched it | **Corrected** — see §2.5 |
| Timeline | All events, newest first, paged by cursor | **Replaced** with an anomaly-only, oldest-first timeline. All events remain in the Event explorer |
| Home graph | 24 one-colour bars; the first bar silently covered only part of an hour | **Replaced** with a rolling 24-hour graph stacked by category, with legend, tooltip and table view |
| Refresh button | Only reloaded the page's data. It did not trigger collection, had no loading or error state, and could not fail visibly | **Fixed** — see §4 |
| Anomalies refresh | Reloaded the whole view whenever new data arrived (every few seconds while events flow) | **Changed** to every 60 s, preserving scroll and selection |
| Home quick-list buttons | Left-aligned flex row with ragged wrapping | **Aligned** to an equal-width grid |
| Collector schedule (2 s), ingestion, deduplication, coverage model | Working | Unchanged (the collector only gained a "pass now" hook) |

## 2. Anomaly rules and history

### 2.1 Separate data, one shared filter

Rule configuration, raw events and detection records stay separate. Nothing is deleted when a rule changes.

Every **active** view uses the same SQL join (`_active_cte` + `ACTIVE_JOIN` in `anomalies.py`):
- the anomaly list
- the grouped view
- the severity cards
- the totals
- the nav badge
- the "Which rules are firing" and "Recently triggered" widgets
- the timeline
- the per-rule "7 days" count

A stored detection is active only when its rule is enabled now **and** it still matches the rule's current channel, Event ID and (for exact-provider rules) provider.

**History** shows every stored detection, with the rule's current state, for example "Rule disabled – hidden from active views".

### 2.2 Switching a rule off

- Its detections disappear from every active view and count at once.
- The response reports how many were hidden.
- New matching events are not flagged while it is off.
- Raw events and detection records are kept, and investigation statuses survive.

### 2.3 Switching a rule on

A background job re-evaluates **only that rule** over the rolling 7-day window. It examines only events of that rule's channel and Event ID that have **no detection for that rule yet** (for example, events collected while it was off).

- **Earlier detections** reappear immediately because they are active again. They are not re-created.
- **Missed events** are flagged, with source "re-evaluation".
- **Duplicates are impossible:** detections are keyed by event and rule (`UNIQUE(event_key, rule_id)`, `INSERT OR IGNORE`).
- **Events older than 7 days** are not flagged.
- **Database access:** the job works in chunks of 2,000 events and takes the database lock briefly per chunk, so collection and the dashboard keep working.
- **Wait time:** the request waits up to 2 s (`GRIFFENDO_EVAL_WAIT_SECONDS`). Larger jobs continue in the background, and the UI shows progress ("Re-evaluating 7 days… n/m"), then refreshes.

**Race conditions:**
- If the rule is switched off during the job, it stops at the next chunk.
- If the rule is edited during the job, it runs again with the new definition.
- Rule changes are serialised.
- Ingest and re-evaluation cannot miss an event: ingest stores before it detects, and the job queries after the switch was saved.

Creating an enabled custom rule, or editing an enabled one, runs the same job.

### 2.4 Persistence

The ON/OFF state was already persisted in `triage.db` and is unchanged. Tests and the Wine run confirm that the active filter and the switch state survive a restart.

### 2.5 Edited and deleted custom rules

**Editing:**
- Detections keep their rule ID and the name and severity stored when they were detected (shown in History and the detail view as "at detection").
- Active views show the rule's current name and severity.
- Detections that no longer match the edited channel or Event ID leave the active views, marked "Rule changed since detection". They are never re-labelled or moved to another rule.

**Deleting:** a soft delete. The rule's detections are hidden from active views and kept in History.

### 2.6 Behaviour change from the v3 request

v3 deliberately did **not** re-create history on enable. The v4 request explicitly asks for it, so enable now re-evaluates automatically. The manual per-rule "Rescan" is kept and never duplicates.

## 3. Timeline, graph and layout

### Timeline (anomalies only, oldest first)

- **Content:** active anomalies (enabled rules) from the rolling last 7 days (not calendar days), plus 5 minutes of tolerance for clock skew.
- **One entry per event:** when several rules flag the same event, they are listed together on one entry ("Also flagged by…"), never as duplicates.
- **Order:** event time, then Windows record ID, then event key. This is stable for equal timestamps and served by a new index.
- **Each entry shows:**
  - time
  - severity
  - anomaly name
  - Event ID
  - rule
  - host
  - channel
  - provider
  - user
  - source address and record ID, when present
- **Clicking an entry** opens the anomaly with all event fields and the original XML.
- **Paging:**
  - cursor in both directions: "Load earlier" at the top, "Load newer" and infinite scroll at the bottom
  - "Oldest" and "Newest" jump buttons
  - at most 1,500 entries are kept on the page; the far end is trimmed and re-loaded on demand
- **Live updates:** new or restored detections are fetched by sequence number and inserted at their **chronological position**. The reader's scroll position is anchored. Rule switches reload the visible range in place.
- **Filters:**
  - search
  - range (7 d / 72 h / 24 h / 1 h)
  - severity
  - Event ID
  - channel
  - host
- **Empty and missing data:** empty states and coverage warnings ("No data collected yet" is never presented as "no anomalies").

### 24-hour graph (home page)

- **Window:** rolling [now − 24 h, now] on each event's own time. Future-dated events are excluded.
- **Buckets:** whole hours of the viewer's local clock (the browser sends its UTC offset). The first and last buckets are partial and labelled as such in the tooltip and table.
- **Categories:** taken only from the stored channel name.
  - Security, System, Application
  - Windows Defender (`Microsoft-Windows-Windows Defender/*`)
  - Other channels (Setup, Sysmon, Task Scheduler, …; the actual channel names are listed under the graph)
  - Unknown channel (none recorded)
- **Colours:** fixed per category (never by rank). They were validated with a colour-vision-deficiency checker:
  - worst adjacent CVD ΔE 9.1
  - normal-vision ΔE 19.6
  - three colours fall below 3:1 contrast on white
- **Not colour-alone:** because of that contrast warning, every bar has a legend with counts, a hover/focus tooltip and a "Show as table" view.
- **Refresh:** on new data (live poll) and on manual Refresh.
- **Empty state:** says the period had no events and that, if collection is not running, this is missing data.

### Layout

- **Quick-list buttons:** a 5-column grid of equal 40 px buttons, falling to 3 columns (≤ 900 px) and 2 columns (≤ 520 px). Checked at 1440, 1024 and 390 px: equal heights, aligned rows, no horizontal scroll.
- **Section headings:** right-hand actions now align with the heading line.
- **Chart:** drawn in real pixels, so labels no longer stretch.

## 4. Refresh and refresh intervals

### Manual Refresh (`POST /api/refresh`)

1. Asks the collector running in this window for an **immediate pass**. That pass also retries channels waiting out an error back-off.
2. Waits for a pass that *started after* the click, up to 20 s (`GRIFFENDO_REFRESH_TIMEOUT_SECONDS`).
3. Clears the server's cached aggregates and reloads the current view. The anomaly list keeps its page and selection, and the timeline keeps its scroll position.

What the UI shows:
- **While running:** the button shows a spinner and "Refreshing…" and is disabled. Double clicks send one request, and the server also serialises concurrent refreshes.
- **Success:** "Refreshed HH:MM · N new events, M new detections".
- **Partial:** some channels failed; the status turns amber and names them.
- **Failure:** red "Collection failed – showing stored data" with the reason. The last-successful time is **not** updated.
- **No collector** (`--no-collect`, snapshot mode, non-Windows) is reported as such, never as success.
- **Missing logs** (Sysmon not installed, for example) are listed but do not count as failures.

### Anomalies view: every 60 s

`GRIFFENDO_ANOMALY_REFRESH_SECONDS`, default 60, minimum 10.

- The timer runs only while the view is open and the tab is visible. It pauses while a dialog is open.
- Unchanged tables are not re-rendered.
- Scroll position, horizontal scroll, page and the selected (highlighted) row are kept.
- A note shows "AUTO-REFRESH EVERY 60 S · UPDATED hh:mm:ss".
- Manual Refresh and the user's own actions (switching a rule, saving a status) update immediately.

### Other schedules are separate

- **Collector:** still polls every 2 s; untouched.
- **Overview and timeline:** follow new data within about 3 s.
- **Nav badge:** updates at the 60 s pace on other views.
- **Quick-list panel:** refreshes only while the overview is visible.

## 5. Performance (measured)

**Receiver and API, 200,000 events (`tools/benchmark.py`, batch 5,000, disk).** v4 was measured before the ingest-index fix below.

| Metric | v3 final | v4 |
|---|---|---|
| Ingest | 4,178 ev/s | 5,070 ev/s (run-to-run spread ≈ ±7%; no regression at this size) |
| Anomaly summary, first call / repeat | 223 / 9.2 ms | 247 / 6.9 ms |
| Anomaly list page (50) | 4.6 ms | **16.1 ms** (slower: active-rule join and count) |
| Overview incl. 24-hour graph, repeat | 1.5 ms | 2.1–3.0 ms; graph first computation 97 ms |
| Anomaly timeline page (200), first / repeat | — | 26.5 / 7.0 ms; newest page 6.6 ms |
| Full anomaly-timeline walk | — | 16,861 entries, 34 pages, 0.62 s, 0 duplicates, equal to reported total |

**1,000,000 events, 84,500 detections** (`tools/benchmark_v4_queries.py`, same database as the v3 1M run):

| Query | v4 |
|---|---|
| Timeline page (200), cold / warm / next / newest | 372 / 4.9 / 4.8 / 4.1 ms |
| Timeline live changes | 12 ms |
| Full timeline walk (fixed clock) | 72,193 entries, 145 pages, 2.1 s; 0 duplicates; equal to reported total |
| Anomaly list page (50) | 40 ms |
| Summary, cold / warm | 990 / 3 ms (v3 after its fix: 1,566 / 3.3 ms) |
| Rules with status, cold | 551 ms (v3: 628 ms) |
| Grouped view, cold | 530 ms |

**Switching a high-volume rule on** (SEC-4624, 200k database, background job):
- First time: 48,234 events evaluated and flagged in **6.2 s**.
- Off and on again: 48,234 detections restored, 0 new, **0.69 s**.

**Fixed while measuring** (all found by measurement):
- **A v3 defect hurt ingest at scale.** The ingest-time detection query looked events up through the Event-ID index instead of the event-key index, costing 226 ms instead of 11 ms per 2,000 events at 1M. It is fixed in `process_events`, and the rule re-evaluation went from 16.2 s to 6.2 s for the same 48k events.
- **The first version of the active join** made timeline pages take 230 ms and list pages 330 ms at 1M. A covering index `(rule_id, event_time, event_id, channel, provider, hostname, event_key)` replaced `idx_anomalies_rule_time`, and the list now picks its page by row ID first.
- **Timeline totals** are no longer recounted on every page.

**Full re-run at 1,000,000 events over 7.5 days, ingested over HTTP** (`tools/benchmark.py`, batch 5,000, disk; `docs/perf/v4_1M_batch5000.json` vs `v3_1M_batch5000.json`):

| Metric (1M) | v3 | v4 |
|---|---|---|
| **Ingest** | 1,784 ev/s (560 s) | **3,295 ev/s (303 s), +85%** (the ingest-index fix) |
| Server memory after ingest | 158 MB | 161 MB |
| Anomaly summary, first call / repeat | 7,241 / 999 ms | **1,257 / 6.9 ms** |
| Overview, first call / repeat | 4,492 / 1.8 ms | 1,955 / 2.6 ms; with 24 h graph 448 / 2.3 ms |
| Anomaly list page (50) | 8.3 ms | **54.5 ms** (slower; see §10) |
| Anomaly timeline, first page / newest page / Critical+High filter | — | 131 → 8.6 ms repeat / 7.5 ms / 36 → 11 ms |
| Full anomaly-timeline walk | — | 84,439 entries, 169 pages, 4.8 s, 0 duplicates, equal to reported total |
| All-events walk (Event explorer API) | 931,785 in 369 s | 932,238 in 337 s, 0 duplicates |

## 6. Tests and results

**`pytest tests`: 210 passed, 0 failed.** This is 195 earlier tests plus 15 new ones in `tests/test_v4_behaviour.py`.
- **Rewritten:** three v3 tests that encoded the old switch semantics.
- **Updated:** one test, because the overview gained a key.

The new tests cover:
- **Switching off:** removes the rule from the list, grouped view, severity totals, widgets and timeline, while keeping History and raw events.
- **Switching on:** restores the window and evaluates events missed while off. A 9-day-old event is not flagged, new events are detected, and repeated toggles and re-sent events create no duplicates.
- **Investigation statuses** survive off/on.
- **Restart:** the switch state and the active filter survive.
- **Large background evaluation:** runs in chunks, stops when the rule is switched off, and later completes exactly once (450 events, no duplicates).
- **Editing a custom rule:** moves the active view to the new definition; old detections are kept and never re-labelled.
- **Timeline:**
  - only active anomalies, oldest first
  - equal timestamps ordered by record ID
  - one entry for an event flagged by two rules, with the highest severity first
  - rule switches respected
  - 230 entries paged both directions with no gaps
  - live changes include late-arriving and restored detections in order
  - empty state; a bad cursor gives 422
- **24-hour graph:**
  - only the last 24 h (25 h-old and future events excluded)
  - Security, System, Application, Defender, Other (Sysmon) and Unknown counted correctly
  - partial first and last buckets
  - buckets on whole local hours for UTC+05:30
- **Refresh:**
  - no collector → "unavailable"
  - failed, timeout, exception and partial results reported correctly
  - concurrent refreshes never overlap
  - a real collector (in-memory log, 60 s interval) collects a new event immediately and reports a failing channel as partial
- **Settings:** the UI interval is 60 s and configurable; the collector interval is unchanged.

**UI acceptance (`tools/ui_acceptance.js`, Playwright, headless Chromium).** Run against the synthetic live demo; Playwright's fake clock tests the 60 s schedule. **All 23 checks passed:**
- **Graph:**
  - covers exactly 24 h
  - 6 legend entries with 6 distinct colours
  - plotted columns equal the buckets, and totals agree
  - tooltip on hover
  - the table lists every bucket
- **Buttons:** equal height, aligned and no horizontal scroll at 1440, 1024 and 390 px.
- **Refresh:**
  - loading state while running
  - one request for a double click
  - success with counts
  - a simulated failure is shown and not reported as success, with the previous success time kept
  - a simulated HTTP 500 is shown and the button is restored
- **Anomalies view:**
  - **no** reload during 50 s while live data arrived, then exactly **one** at 60 s
  - the schedule note is shown
  - the selected row and the scroll position (900 px) are unchanged after an automatic refresh
- **Rule switch in the UI:**
  - SEC-4625 off: severity card, list and timeline go to 0, History keeps 107
  - SEC-4625 on: 107 restored plus 1 event collected while it was off, consistent everywhere
- **Timeline:**
  - oldest first, no duplicates
  - live anomalies inserted in order (121 → 124 entries)
  - an entry opens the anomaly with its XML
- **Console:** no JavaScript errors, apart from the deliberately simulated HTTP 500.

**Rebuilt exe:**
- **Integrity** (`tools/verify_exe.py`), all passing:
  - all 11 Griffendo modules (new: `logplatform.activity`) and the launcher compile to code identical to `src/`
  - assets and catalog are byte-identical to the repository
  - 60 package entries and 789 bundled modules are byte-identical to the original exe
- **Under Wine 9.0** (not real Windows):
  - starts in 4–20 s; reports version 0.4.0
  - **Refresh** really ran a pass (0.43 s) and honestly reported "Collection failed" for all 9 channels (Wine has no PowerShell or event-log service)
  - **Synthetic ingest:**
    - timeline: 25 entries, oldest first
    - 24 h graph: 25 events, with the 26 h, 30 h and 9-day-old events excluded
  - **Switching SEC-4625:**
    - off: hid 20 detections
    - after a restart: still off, timeline 5
    - on: restored 20 and evaluated the 1 event ingested while off (timeline 26)
    - off/on again: 0 new, History 21
  - **Dashboard** loaded with 0 JavaScript errors and showed the failed refresh state

**Not executed here (needs real Windows):**
- reading real logs through the native API or PowerShell
- a manual Refresh that actually collects from Windows
- real end-to-end latency

The refresh path into the collector was tested with an in-memory log and the real HTTP receiver.

## 7. Files changed

**Backend:**
- `src/logplatform/anomalies.py`: active-rule filter; per-rule re-evaluation jobs; active counts in summary, rules and widgets; rule-state labels; covering and timeline indexes; ingest index fix.
- `src/logplatform/timeline.py`: `anomaly_page` (anomaly timeline).
- `src/logplatform/activity.py` (new): 24-hour category graph.
- `src/logplatform/app.py`:
  - new endpoints `/api/timeline/anomalies` and `POST /api/refresh`
  - `activity_24h` in `/api/overview`
  - refresh and evaluation fields in `/api/live` and `/api/config`
  - version 0.4.0
- `src/logplatform/settings.py`: new intervals.
- `src/agent/continuous.py`: wake-up and forced pass (`request_collection`); channel failures split from "log not present".
- `src/launcher.py` and `tools/demo_server.py`: register the refresh hook.

**UI:**
- `web/app.js`:
  - graph, refresh flow and view-scoped timers
  - 60 s Anomalies refresh with scroll and selection preservation
  - rule-switch messages and evaluation progress
  - new timeline
- `web/index.html`, `web/styles.css`

**Tools:**
- `tools/benchmark.py` (v4 endpoints)
- `tools/benchmark_v4_queries.py`
- `tools/ui_acceptance.js`
- `tools/repack_exe.py` (adds `logplatform.activity`)

**Tests:**
- `tests/test_v4_behaviour.py` (new)
- `tests/test_rules_counts.py`, `tests/test_anomalies.py` (updated for the requested semantics)

## 8. Build and run

Unchanged from v3:
```
pip install fastapi==0.143.1 uvicorn==0.54.0 pydantic==2.14.1 requests==2.34.2
python src/launcher.py                       # Windows: dashboard + continuous collector
python tools/demo_server.py 8770 --live-every 1   # any OS: synthetic live demo
python -m pytest tests
node tools/ui_acceptance.js <screenshot-dir> http://127.0.0.1:8770/
python3.12 tools/repack_exe.py "original Griffendo.exe" dist/Griffendo.exe
python3.12 tools/verify_exe.py "original Griffendo.exe" dist/Griffendo.exe
```

New settings:

| Variable | Default | Meaning |
|---|---|---|
| `GRIFFENDO_ANOMALY_REFRESH_SECONDS` | 60 | Anomalies view auto-refresh (min 10) |
| `GRIFFENDO_REFRESH_TIMEOUT_SECONDS` | 20 | How long Refresh waits for the collector's pass |
| `GRIFFENDO_EVAL_WAIT_SECONDS` | 2 | How long switching a rule on waits before the re-evaluation continues in the background |
| `GRIFFENDO_EVAL_CHUNK` | 2000 | Events per re-evaluation chunk |

## 9. Security

- **Nothing new executes system commands.** Refresh only wakes the existing read-only collector.
- **Write endpoints** (`/api/refresh`, rule changes) refuse cross-origin requests, as before.
- **No new data leaves the machine,** and nothing is deleted. Raw events, detection records and audit data are never removed by rule changes.
- **Error messages** shown for failed collection contain channel names and the error text only, no event content.

## 10. Remaining limitations

1. **Real Windows validation is still outstanding** (see §6).
2. **Ingest still slows as the store grows,** from about 5,000 events/s at 200k to an average of 3,295 events/s over a 1M-event load. It is CPU-bound on XML parsing and index maintenance.
3. **The anomaly list page is slower than in v3** (16 ms at 200k, 54 ms at 1M, against 4.6 and 8.3 ms) because its count now applies the active-rule join. Summary and rules are much faster than v3. First-call costs at 1M remain about 0.5–1.3 s for summary, rules and grouped.
4. **The timeline's "N anomalous events in range"** is exact on (re)load. Between reloads it is advanced by live additions, which may slightly over-count when an already-listed event gains another rule.
5. **Changing exact-provider matching** on a custom rule hides non-matching old detections, but does not delete or re-label them (by design).
6. **Graph colours:** three colours have below 3:1 contrast against white. The legend with counts, the tooltip and the table view are provided for that reason.
7. **The exe is unsigned,** as the original.
