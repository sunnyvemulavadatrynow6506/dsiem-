# Griffendo v3: rule management, real-time collection, 7-day timeline, performance

**Built on:** the v2 package you received (`Griffendo_v2_source.zip`, commit `1cfeb6a`). All v2 features are kept.

**What's in v3:**
- every anomaly rule has a persistent ON/OFF switch, and users can add, edit and delete their own Event ID rules
- the collector now reads Windows logs **continuously** and resumes after a restart
- the timeline reaches every event in the last 7 days
- coverage is explained in plain terms instead of a single "Data coverage" number
- every rule shows its detection counts

**Tests:** 195 automated tests pass on Linux, and the rebuilt exe was exercised under Wine. Performance figures below were measured with synthetic data; none are estimated.

**Not yet validated on a real Windows host:** the new native Windows Event Log reader (`wevtapi.dll` via `ctypes`). It falls back automatically to the v2 PowerShell reader if it fails its start-up self-test, but it must still be checked on Windows (§10).

---

## 1. What was inspected and what was actually wrong

| Area | File(s) | Finding |
|---|---|---|
| Collection | `agent/collector.py` | One **snapshot per launch**. The collector recorded each log's newest record number at start, read up to it, then stopped. **Events written after launch were never collected** until the next restart. |
| "2,000 at a time" | `agent/collector.py`, `logplatform/app.py` | `BATCH_SIZE = min(2000, …)` in the collector and `MAX_INGEST_EVENTS = 2000` in the receiver were hard-coded. The real bottleneck sat behind them: each channel was read **222 events per new `powershell.exe` process** (2000 ÷ 9 channels), and each process ran two `Get-WinEvent` queries. A 100,000-event backlog needs ****463** PowerShell launches** (counted by `tools/benchmark_collector.py`). |
| Restarts | `collector.py`, `db.py` | Cursors and spool were in `:memory:` and reset to 0 on every start, and the event store was in memory too. **Every launch re-read and re-parsed the entire logs.** |
| Timeline | `app.py /api/timeline`, `app.js` | `LIMIT 100`, no paging, and sorting on raw timestamp strings. With 200,000 events only **100 (0.05%)** were reachable. |
| Dashboard | `app.py /api/overview` | Full-table `COUNT(DISTINCT …)` every 30 s: **531 ms** at 200k events. |
| UI refresh | `app.js` | Only Overview and Anomalies refreshed (every 30 s). Timeline and Event explorer never refreshed. |
| Parsing | `logplatform/parser.py` | `UserData` nested deeper than two levels was dropped. `EventRecordID`, `Channel` and `Computer` from the XML were not captured. Malformed events were stored silently with no diagnostics. |
| Data coverage | `anomalies.py` | One label built from "earliest stored event vs window start". It could not tell a quiet log from a wrapped or cleared one. |

## 2. What changed

### Collection (`agent/continuous.py`, `agent/sources.py`)
- **Continuous mode is the default.**
  - Every 2 s (`WINLOG_INTERVAL_SECONDS`) each channel is read from its saved cursor (the last EventRecordID read).
  - New events are read first. History ("backfill") is read separately, **newest first**, in bounded slices, so recent days appear first and backfill never delays live events. Live events also go first in the delivery queue.
  - `--snapshot` / `WINLOG_MODE=snapshot` keeps the v1/v2 behaviour.
- **Two readers.**
  - **Native**: Windows Event Log API (`EvtQuery`/`EvtNext`/`EvtRender`) through `ctypes`. No process per read and no new binaries.
  - **PowerShell**: the v2 method, used automatically if the native reader fails its self-test. `WINLOG_BACKEND` can force either.
- **Persistent state** in `%LOCALAPPDATA%\Griffendo\collector.db`:
  - cursors survive restarts, so collection **resumes where it stopped** instead of re-reading
  - events are spooled to disk and removed only after the receiver acknowledges them, so an interrupted batch is re-sent, not lost
  - if the receiver's database is new (deleted, or memory mode), the collector notices via a store id and re-sends history
- **Event identity:** `sha256(host | channel | EventRecordID | TimeCreated | EventID)`. Re-sends are deduplicated, and records renumbered after a log clear stay distinct.
- **Gaps and clears are detected and reported:**
  - record numbers skipped between reads (log wrapped while the collector was off) are counted as lost
  - a cleared log is detected and reading restarts from record 1
- **Failures back off per channel** and are reported (unavailable / access denied / empty / disabled / error); other channels keep going.
- **Live channel list.** The collector asks the receiver which channels enabled rules need (`/api/collector/config`), so enabling a rule on a new channel takes effect without a restart.
- **Health reporting** every 10 s: per-channel state, last success, last error, backfill progress, records lost, log retention metadata, event→collection latency, spool size and delivery rate.

### Storage and API (`logplatform/db.py`, `timeline.py`, `app.py`)
- **Events, detections and collector state are on disk** (SQLite, WAL) in the Griffendo data folder.
  - Retention is 14 days by event time (`GRIFFENDO_RETENTION_DAYS`); detections are kept.
  - `GRIFFENDO_STORAGE=memory` restores the v1/v2 volatile behaviour.
  - Collected event XML is now stored on the local disk. It never leaves the machine.
- **New columns and indexes.** An `event_time` column (normalised UTC), plus indexes on `(event_time, id)`, `(channel, event_time)` and `(event_id, channel)`; one redundant index was dropped. Ingestion time, collection time and event time are recorded separately.
- **Ingest limit is now configurable** (`LOGPLATFORM_MAX_INGEST_EVENTS`, default 10,000; 128 MB). The collector's delivery batch defaults to **5,000**, chosen from the measurements in §4.
- **`/api/timeline/page`** uses keyset (cursor) pagination over the 7-day window. Pages never shift, skip or repeat while new events arrive, and `newer_than` fetches events above the top row for live updates. The old `/api/timeline` is unchanged.
- **Faster refreshes.**
  - `/api/live` is a cheap change marker the UI polls every 3 s (`GRIFFENDO_UI_REFRESH_SECONDS`); a view refreshes only when something changed.
  - Whole-table aggregates are cached and recomputed only when data changes.
- **Parser fixes.** Deep `UserData` is flattened, and `EventRecordID`, `Channel` and `Computer` are captured. Malformed events, missing Event IDs and missing timestamps are written to `ingest_diagnostics`; problems are recorded, event content is not.

### Rules (`logplatform/anomalies.py`, `state.py`)
- **ON/OFF switch on every rule**, persisted in `triage.db`. The switch only changes after the server confirms the save; a failed save shows an error and leaves it unchanged.
  - **Disabling** stops new detections and keeps all history.
  - **Re-enabling** applies to newly collected events only. Older events are re-examined only through an explicit **Rescan** on that rule, and rescanned detections are labelled as such.
- **Custom rules** (Add / Edit / Delete):
  - **Required fields:** name, Event ID (0–65535), category, severity (Critical–Informational), provider, channel, description, relevance, recommended action, initial state.
  - **Optional fields:** rule id, author, tags, MITRE ATT&CK ids (recorded as entered, not verified), source URL, display label, fields to show, notes.
  - **Validation:** checks every field, refuses duplicate or previously used rule ids, and only accepts channel names that are safe for the collector.
  - **Marking:** custom rules are labelled *Custom · unverified*.
  - **Built-in protection:** built-in rules can only be switched on or off. Editing or deleting one is refused (403).
  - **Deleting** is a soft delete: detections stay in History with the rule's metadata.
  - **The recommended action is display-only guidance and is never executed.**
- **Overlap policy.** Several enabled rules may target the same channel and Event ID. Each records its own detection for the matching event, so nothing is discarded.
  - The editor shows the overlapping rules and requires explicit confirmation.
  - Counts distinguish *detections* (event × rule) from *event occurrences* (distinct events).
- **Exact provider matching** is available per custom rule. It is off by default, so detection stays "channel + Event ID".
- **Per-rule counts from stored detections:**
  - total detections, distinct events and hosts
  - count in the last 7 days
  - count since the rule was last enabled
  - count created by rescans
  - first and last detected
- **Reliability states per rule:**
  - Operational – has triggered
  - Operational – never triggered
  - Enabled – source unavailable
  - Enabled – source not confirmed
  - Disabled
  - Deleted

  An ON switch alone never shows a rule as operational.

### Coverage (Feature 6)
"Data coverage" is now split into five separate values:
- **analysis window**
- **available log coverage** (earliest–latest relevant events)
- **collection health** (collector running, stale, snapshot-only, or none)
- **missing or unavailable data**, with reasons
- **last successful collection**

On the Anomalies page the old "Data coverage" card is now labelled **Available log coverage**. It shows a state (Verified / Partial / Unknown / Unavailable / No data), never a percentage, and opens the explanation panel when clicked.

Each channel gets one of these statuses:

| Status | Shown when |
|---|---|
| **Verified** | Readable, no record gaps, and retention reaches the window start (or the Windows log still holds its first record, so nothing was lost) |
| **Partial** | Backfill running, records lost, log cleared in the window, log wrapped before the window start, retention unconfirmable, or the collector stale |
| **Unknown** | No collector report |
| **Required channel unavailable** | The channel cannot be read |

**No percentage is shown**, because time span does not prove completeness. The info panel says what is measured and what is not proven. When nothing has been collected, the page says "No data collected yet" and the severity cards show "—", not 0.

### UI
- **Anomalies page.**
  - Dashboard cards: occurrences, distinct anomalies, rules on/off/triggered/never/unavailable, window, collection health, coverage.
  - A sortable **Rule activity** table and a **Recently triggered** list.
  - Tabs: Detections (7 days), Grouped, **History (all stored, including disabled/deleted rules)**, **Anomaly Rules** (search, filter, sort, switches, Add/Edit/Delete, Rescan, per-rule detections), and **Coverage & collection** (health, per-channel coverage, latency, Windows log metadata, parsing diagnostics).
- **Timeline.**
  - Every event in the 7-day window, newest first (or oldest first), loaded 200 at a time with automatic "load older" as you scroll.
  - Day headers, darker and larger text (13–14 px), and clearer Event ID badges.
  - Filters: time range, Event ID, channel, provider, host, level, anomaly severity, search.
  - A coverage warning, a LIVE indicator with last-updated time, and new events appearing at the top (or a "N new events – show" banner if you've scrolled down).
  - The app has only a light theme, and that is kept; there is no dark theme.
- **Live status** in the top bar: polling interval, collector heartbeat age, and how long after occurring the last live event was displayed.

## 3. Tests (all executed on Linux, CPython 3.12, the exe's exact library versions)

**`pytest`: 195 passed, 0 failed** (163 v2 tests, updated where v3 intentionally changed semantics, plus 32 new):

- **Rule management:**
  - disable stops new detections and keeps history
  - re-enable does not recreate old alerts; explicit rescan does, labelled
  - settings persist across restart
  - a failed save returns 503 and leaves the rule unchanged
  - cross-origin writes refused
  - custom rule flags every match
  - overlap needs confirmation, then both rules record
  - full validation matrix
  - duplicate ids refused; built-in edit/delete refused
  - edit keeps old detections' metadata; delete keeps history
  - exact-provider opt-in
  - a new-channel rule shows "source not confirmed" and then "unavailable", never active
- **Counts:** no double counting on reprocessing or rescan; preserved across restart and while disabled; 7-day count versus total as the window moves; dashboard figures match stored data.
- **Timeline and performance:**
  - all 5,200 window events reachable, 11 pages, no duplicates, correct order both directions, events outside the window excluded
  - a single 8,000-event request accepted
  - paging stays stable while newer and older events are inserted mid-walk
  - `newer_than` returns exactly the new events
  - filters and bad-cursor handling work; the legacy endpoint still works
- **Collection** (real collector and real HTTP receiver, synthetic log):
  - an event written after startup is visible and flagged within one pass
  - live events land while backfill is still running
  - restart resumes from the saved cursor (3 new events sent, 300 old not re-sent)
  - a reset receiver store triggers a re-read
  - a channel failure is visible, backs off and recovers
  - a delivery outage keeps events spooled and delivers them later
  - records lost to a log wrap are counted and coverage becomes partial
  - a cleared log is re-read from record 1
  - unavailable, access-denied and empty channels are reported correctly
- **Parsing:** representative Security, System (Qualifiers + Binary), Event Log `UserData` (nested), Defender (spaced names, +05:30 offset) and unnamed-Data fixtures; malformed XML, missing EventID and missing time are diagnosed without storing content.
- **Coverage:** no data is not reported as zero anomalies; partial for unconfirmed or wrapped retention; verified only when the log still holds record 1; a stale collector gives partial.
- **UI** (Playwright, headless Chromium, against the live synthetic demo; script in `tools/`):
  - the rule switch persists, and the validation, overlap prompt and save flow work
  - the timeline loads 200 rows (first rows in **39 ms**, render 26 ms) and "load older" adds 200 with **0 duplicate rows**
  - live events appeared at the top **1.9 s** after they occurred
  - no JavaScript errors apart from the intended 409 overlap response
  - no horizontal scroll at 390 px
- **Rebuilt exe under Wine:** see §6.

**Not executed here (needs Windows):**
- the native reader against real logs, including the start-up self-test and fallback
- the PowerShell reader's new scripts
- reading Security as Administrator
- real Defender, Sysmon and Task Scheduler channels
- log metadata from `Get-WinEvent -ListLog`
- real event-to-display latency on a Windows host

## 4. Measurements (synthetic data, this Linux container; raw JSON in `docs/perf/`)

Receiver and API, 200,000 events over 7.5 days, ingested over HTTP exactly as the collector does (`tools/benchmark.py`):

| Metric | v2 (memory, 2,000 cap) | v3 disk, batch 2,000 | v3 disk, batch 5,000 (default) | v3 disk, batch 10,000 |
|---|---|---|---|---|
| Ingest throughput | 5,422 ev/s | 3,560 ev/s | 4,484 ev/s | 5,168 ev/s |
| Server memory after ingest | 597 MB | 132 MB | 153 MB | 195 MB |
| Overview API (median) | 531 ms | 1.6 ms | 2.1 ms | 1.5 ms |
| Anomaly summary API (median, before the aggregate fix below) | 196 ms | 102 ms | 115 ms | 110 ms |
| Live-change check | — | 2.2 ms | 2.5 ms | 2.2 ms |
| Timeline page (200 rows) | n/a (100-row cap) | 26 ms | 36 ms | 26 ms |
| Events reachable in timeline | **100** | **186,640 (all)** | **186,643 (all)** | **186,644 (all)** |
| Full 7-day timeline walk | impossible | 19.9 s, 374 pages, 0 duplicates | 20.7 s | 21.1 s |

"Median" is the median of repeated calls with unchanged data, so it mostly shows cached results. The **first call** after new data arrives is the honest worst case:

| First call (cold) | v2 | v3 before fix (batch 5,000) | v3 final (batch 5,000) |
|---|---|---|---|
| Overview | 576 ms | 354 ms | 308 ms |
| Anomaly summary | 196 ms | **767 ms** (slower than v2) | **223 ms** (repeat: 9.2 ms) |
| Ingest throughput | 5,422 ev/s | 4,484 ev/s | 4,178 ev/s (run-to-run spread ≈ ±7%) |

**Aggregate fix (found by measuring at 1M events).** Two problems were behind the slow first calls:
- **Wrong index for the cleared-log check.** It used the time index and scanned every event in the window. It now uses the (Event ID, channel) index: 2,772 ms → under 1 ms at 1M events.
- **Caches cleared too often.** The collector's 10-second health report wiped every cached aggregate, and the summary's detection counts were never cached. Health reports now keep data-keyed caches, and the detection counts are cached until new data arrives or a status changes.

Measured on the same 1M-event database with `tools/benchmark_existing.py` (`docs/perf/v3_1M_aggregates_*.json`):

| 1M events, 84,500 detections | Before: cold | Before: warm | After: cold | After: warm |
|---|---|---|---|---|
| Anomaly summary | 4,416 ms | 824 ms | 1,566 ms | 3.3 ms |
| Rules list | 3,556 ms | 1.6 ms | 628 ms | 2.8 ms |
| Coverage | 3,267 ms | 1.7 ms | 295 ms | 1.2 ms |
| Overview | 1,404 ms | cached | 1,371 ms | cached |

**Scale test: 1,000,000 events over 7.5 days, batch 5,000, disk** (`docs/perf/v3_1M_batch5000.json`, measured before the aggregate fix):
- **Ingest:** 1,784 ev/s on average, slowing as the database grows (index maintenance). The 1 GB payload took 9.3 min.
- **Server memory:** 161 MB, flat; v2 needed about 600 MB for 200k events.
- **Timeline:** 200-row page 95–105 ms, filtered page 244 ms. A full walk of the 7-day window returned 931,785 events in 1,864 pages (369 s), with 0 duplicates, and matched the reported total exactly.
- **Event explorer:** first page 17.6 ms, filtered 130 ms. Live-change check: 2.1 ms.
- **Overview at this size** costs about 1.4 s once per 10 s cache period, because it counts the whole store (see §9).

**Memory mode (`GRIFFENDO_STORAGE=memory`), 200k @ 5,000:** 6,398 ev/s (faster than v2's 5,422), 689 MB RAM, summary 444 ms first call / 82 ms median (before the fix).

**Collector pipeline, 100,000 events in a synthetic log** (`tools/benchmark_collector.py`, `docs/perf/v3_collector_100k.json`). Windows read cost is excluded, so this is the pipeline's ceiling:
- **Backfill:** read → spool → HTTP → store → detect at 6,693 ev/s (14.9 s total)
- **Time to first events on the dashboard:** 0.54 s (live and newest data are delivered first)
- **Live latency, event written to visible in the API, 20 samples at the 2 s poll:** median 1.58 s, p95 1.63 s, max 2.07 s
- **PowerShell launches for the same backlog:** v2 would start **463** `powershell.exe` processes; v3 with the native reader starts 0

**What the numbers mean:**
- **Ingest throughput per request did not improve.** v3 writes to disk and maintains more indexes, so at the same 2,000 batch it is slower than v2's in-memory store. Larger batches recover most of it, and memory mode (no disk) is faster than v2. The 5,000 default sits at the knee: +26% over 2,000 for +21 MB, while 10,000 adds +15% more for +42 MB.
- **The loading-time gain is that history is read once.** v2 re-read and re-parsed every log on every launch. v3 reads it once and afterwards only reads new records.
- **On Windows the collector, not the receiver, was the bottleneck.** The native reader removes the **463** PowerShell launches per 100,000 events. I could not measure Windows read speed here.

## 5. Build and run

- **Run from source (any OS; collection needs Windows):**
  ```
  pip install fastapi==0.143.1 uvicorn==0.54.0 pydantic==2.14.1 requests==2.34.2
  python src/launcher.py [--snapshot] [--interval 2] [--no-collect]
  ```
- **Synthetic live demo (no Windows):** `python tools/demo_server.py 8766`
- **Tests:** `python -m pytest tests`
- **Benchmarks:**
  ```
  python tools/benchmark.py --src src --events 200000 --batch 5000
  python tools/benchmark_collector.py --events 100000
  python tools/benchmark_existing.py <data folder>   # cold/warm dashboard aggregates on an existing store
  ```
- **Rebuild the exe** (CPython 3.12 + `pyinstaller==6.22.3`, any OS):
  ```
  python3.12 tools/repack_exe.py "original Griffendo.exe" dist/Griffendo.exe
  ```
  This keeps the original bootloader and libraries byte-for-byte and replaces only the Griffendo modules, launcher, web assets and catalog. Check the result with `python3.12 tools/verify_exe.py "original Griffendo.exe" dist/Griffendo.exe`. Every module used is present in the original bundle (checked), so no binaries were added.

## 6. Rebuilt executable

`dist/Griffendo.exe` (v3). See `SHA256SUMS.txt` in the exe zip.

**Integrity check** (`tools/verify_exe.py`, all passing):
- all 10 Griffendo modules and the launcher compile to code identical to `src/`
- the web assets and catalog are byte-identical to the repository
- the other 60 package entries and 789 bundled library modules are byte-identical to the original exe

**Run under Wine 9.0 on Linux** (not real Windows; collection on, `--port 8823`, synthetic events posted to the ingest API):

| Check | Result |
|---|---|
| Starts, dashboard served | yes, in 4–18 s (first run unpacks) |
| Native reader self-test | failed as expected (Wine's `wevtapi` is a stub): "EvtQuery failed … using PowerShell" is shown in Collector health |
| PowerShell fallback | Wine has no PowerShell; all 9 channels shown as **Collection error / unavailable**. Coverage reads "Channel unavailable", not "0 anomalies" |
| Bundled catalog | loaded from the exe, 134 built-in rules, 0 errors |
| Storage | on disk, in the folder given by `GRIFFENDO_STATE_DIR` (`%LOCALAPPDATA%\Griffendo` by default) |
| Ingest 32 synthetic events, then the same 32 again | 32 inserted, then 0 (deduplicated) |
| Disable SEC-4625 | saved; its 30 detections kept |
| Custom rule with missing fields | 422 with per-field errors |
| Custom rule (Event 7009) | 201, marked "User-defined rule – not verified"; a rescan created 1 detection, labelled as rescan |
| Delete a built-in rule / cross-origin write | 403 / 403 |
| **Restart the exe** | 32 events, SEC-4625 still off with 30 detections, custom rule present with its detection |
| Dashboard (Playwright against the exe) | 135 rules listed (134 + 1 custom), timeline shows all 32 events with the "Required channel unavailable" warning, 0 JavaScript errors |

Real Windows collection could not be tested here (§9).

## 7. Security and data handling

- **Read-only collection.** The collector only reads event logs (Evt\* query APIs or `Get-WinEvent`). Nothing deletes, alters or clears logs, changes audit policy, enables logs, or installs software.
- **Recommended actions are text.** Custom-rule actions are never executed.
- **Network.** Data goes only to the configured receiver (localhost in the launcher; HTTPS required for remote receivers, unchanged). The dashboard binds to 127.0.0.1.
- **Write protection.** Write APIs refuse cross-origin requests. Rule fields are validated, and channel names are restricted so they are safe inside PowerShell and XPath.
- **New on-disk data.** `%LOCALAPPDATA%\Griffendo` now holds:
  - `griffendo.db` — collected event XML, pruned after 14 days
  - `triage.db` — statuses and rule settings
  - `collector.db` — cursors and undelivered events

  These files carry the same sensitivity as the Windows logs themselves. Use `GRIFFENDO_STORAGE=memory` if they must not persist.
- **Diagnostics hold no event content**, only the problem and the record number.

## 8. Behaviour changes to be aware of

- **History limit for the four original channels.** They are read back 14 days on first run (`WINLOG_BACKFILL_HOURS`, `0` = whole log as in v2). The Overview "all retained" counts therefore mean the last 14 days.
- **Event ids changed format.** v2 investigation statuses don't carry over to v3 detections (v2 was delivered one day earlier).
- **Rescan stats.** A full rescan no longer reports out-of-window events as "examined" (they are excluded in SQL).

## 9. Known limitations and outstanding work

1. **Windows validation is outstanding.** This covers the native `wevtapi` reader and the self-test/fallback path, the PowerShell scripts, `-ListLog` metadata, and real latency. The `ctypes` binding follows the documented Evt\* signatures but could not be executed against a real Event Log service here.
2. **Polling, not push.** v3 polls each channel every 2 s with the native API instead of using `EvtSubscribe` push notifications, to keep the untested native surface small. Typical delay is up to the interval plus delivery time.
3. **Ingest throughput is CPU-bound** in XML parsing and index maintenance. On this machine with persistence it is about 4,200–4,500 events/s up to 200k stored events, falling to an average of 1,784 events/s over a 1M-event load. A very large first-run backfill, for example a 1 GB Security log, still takes minutes, but only once.
4. **Overview and first-call cost at very large stores.** At 1M events the Overview counts the whole store (~1.4 s every 10 s while someone is viewing it), and the first anomaly summary after new data costs ~1.6 s. Up to 200k events these are ~0.2–0.3 s. Incremental counters would remove this; not done.
5. **Single-writer database.** All database access is serialised by one lock, as in the original design; reads wait during an ingest transaction (~1 s per 5,000-event batch).
6. **No retention metadata without PowerShell.** When `Get-WinEvent -ListLog` is unavailable, retention cannot be confirmed and coverage stays "Partial (unconfirmed)" by design.
7. **Exe is unsigned**, like the original.
