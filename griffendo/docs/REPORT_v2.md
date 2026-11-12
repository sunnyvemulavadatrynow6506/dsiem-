# Griffendo: Event-ID Anomaly Detection

**What changed:** Griffendo now has an **Anomalies** page. It flags every collected event from the last 7 days whose channel and Event ID match an enabled rule in a configurable catalog. The catalog has 134 rules: all 47 from your spreadsheet plus 87 additions, with 116 enabled. Nothing else is checked: no thresholds, no correlation and no field conditions.

**Rebuilt exe:** `dist/Griffendo.exe` is a byte-level repack of your original exe. The bootloader and every untouched library are unchanged. The exe was run under Wine on Linux and its API, UI and status persistence were exercised. It has **not** yet been run on a real Windows host against real event logs.

---

## 1. What was in the two files

### `griffendo exe file.zip`
The zip held a second zip, `files.zip`, which contained:

| File | What it is |
|---|---|
| `Griffendo.exe` (16.3 MB) | A PyInstaller **6.22.3** one-file build of CPython **3.12**, x64 console app, **not code-signed**. I identified the version by matching the bootloader byte-for-byte and by comparing the loader modules. |
| `app.js`, `index.html`, `styles.css` | The dashboard front end, byte-identical to the copies inside the exe. |
| `parser.py` | The event XML normaliser, bytecode-identical to the bundled `logplatform.parser`. |

**Source for everything else had to be recovered.** The backend source was not in the zip. The rest of the app exists only as bytecode inside the exe: `launcher`, `agent.collector`, `logplatform.app`, `logplatform.db` and the two package `__init__` files. I extracted the bundle and decompiled it (pycdc gives only a partial result for 3.12). I then rebuilt each module by hand from the CPython 3.12 disassembly. Every reconstructed module recompiles to the same instruction stream, constants and names as the shipped bytecode (`tools/` comparator; git commit `18519c1` is that baseline). Ignoring line numbers, this is the original source.

**Architecture as found:**

- **Launcher.** It picks a localhost port and generates a random ingest token. It then starts FastAPI 0.143.1 / Starlette 1.8.0 on Uvicorn 0.54.0, bound to 127.0.0.1, opens the browser and runs **one** collection snapshot.
- **Collector (`agent/collector.py`).** It runs `powershell.exe Get-WinEvent ... ToXml()` against **System, Security, Setup and Application only**. It reads each log from record 0 up to a watermark taken at start, spools the raw XML and POSTs batches to `/api/ingest` with a bearer token. Event identity is `sha256(host|channel|record_id|raw_xml)`.
- **Receiver (`logplatform/app.py`, `db.py`).** Pydantic validation **rejected any channel other than those four**. Storage is a *volatile* shared in-memory SQLite database holding at most 2 million events, so it is empty after every restart and refilled by the next snapshot.
- **Statistics.** The overview totals, 24-hour trend, top Event IDs, channels and processes come from SQL over that store. Labels for 6 IDs were hard-coded in `EVENT_LABELS`, and `app.js` grouped about 40 IDs into "activity types" on the Endpoints page.
- **UI.** A single-page app with five views: Overview, Event explorer, Processes, Timeline and Endpoints.
- **Before this work:** no anomaly or alert rules existed anywhere.

### `Griffendo_Anomaly_Event_IDs.xlsx`
The workbook has three sheets:

- **Summary:** COUNTIF formulas.
- **Anomaly Events:** 47 rows covering Critical 11, High 13, Medium 18 and Optional (Sysmon) 5, with 36 on existing channels and 11 needing new ones.
- **Notes:** the removed IDs, false-positive guidance, audit-policy guidance, and 3003.

All 47 rows are preserved and enabled. Three were corrected:

- **6008:** renamed to "Previous system shutdown was unexpected".
- **6416:** category changed from "Data exfiltration" to "Device monitoring", and "(USB)" dropped from the name.
- **4740:** wording changed to "User account locked out".

The channel questions raised in the prompt were checked: **5025** and **1100** really are in the Security log (Microsoft's "Audit Other System Events" and Event Log service documentation).

---

## 2. Detection behaviour (`src/logplatform/anomalies.py`)

- **Trigger.** An event is flagged when `match_rule(channel, event_id)` finds an enabled rule and its time is inside the window. That function is the only detection decision in the code.
- **Window.** The window is `[now − 7 days, now]`, inclusive at both ends, in UTC. It uses each event's own `TimeCreated`. A 5-minute tolerance absorbs clock skew. Events with later timestamps, for example after a clock change, are counted and reported, not hidden.
- **Detection time.** New events are flagged **at ingest**, in the same request that stores them, so nothing waits for a full scan. A full rescan is available from the UI and API.
- **One record per event.** Each matching event is its own record, keyed by `sha256(event_key|rule_id)`.
  - Reprocessing uses `INSERT OR IGNORE`, so the same event is never stored twice.
  - Distinct events are never merged, even when record IDs repeat after a log clear.
  - The "Grouped by rule & host" view is display-only, and every occurrence stays one click away.
- **Missing fields never block a flag.**
  - Analyst fields that are absent are shown as "not present in this event".
  - An event with no timestamp falls back to its receive time and says so.
  - An event whose provider differs from the one the rule expects is still flagged, marked "PROVIDER DIFFERS", and explained in the detail view.
- **Evidence.** Each detection keeps a copy of the event data and raw XML. The evidence survives even if the event later falls out of the in-memory store.
- **Disclaimer.** Every detail view states that a flag means the configured ID occurred and may be legitimate.

## 3. Catalog

The catalog lives in `catalog/anomaly_catalog.json`, version `2026.10.26-1`. It is generated by `tools/build_catalog.py`, which also checks that there are no duplicate rules and that all 47 spreadsheet rows are present.

The full catalog, row-by-row status, difference report (sections 1–7 of the prompt), reviewed-but-excluded IDs and channel list are in **`docs/Griffendo_Anomaly_Event_IDs_v2.xlsx`**. That workbook keeps your workbook's layout and formulas.

| Severity | Rules | Enabled | From your sheet |
|---|---|---|---|
| Critical | 14 | 14 | 11 |
| High | 29 | 29 | 13 |
| Medium | 47 | 47 | 18 |
| Low | 18 | 12 | 0 |
| Informational | 16 | 4 | 0 |
| Optional (Sysmon) | 10 | 10 | 5 |
| **Total** | **134** | **116** | **47** |

- **Additions by origin.**
  - 45 came from the prompt's candidate list.
  - 39 came from research: Microsoft "Appendix L: Events to Monitor", the Defender event list, the Sysmon reference and similar sources.
  - 3 were first found in Griffendo's own code: 4739, 5156 and 5157.
- **Catalogued but disabled.** 18 high-volume IDs would bury everything else if enabled: 4624, 4672, 4688, 4768, 4769, 4776, 4656, 4663, 4660, 4670, 4798, 4799, 5140, 5145, 5156, 5157, 4103 and 4104. Setting `"enabled": true` turns any of them on.
- **Reviewed and excluded.** 27 IDs were left out, each with a reason. Examples: 3003 could not be verified; 7036 and 4689 are routine; ID 1 in the System log is ambiguous across providers.
- **"Optional" severity.** The spreadsheet's "Optional (Sysmon)" tier is kept as its own severity bucket. It describes a prerequisite, not impact, so you may want to re-tier those rules.
- **Changing rules without a code change.**
  1. Copy the JSON to `%LOCALAPPDATA%\Griffendo\anomaly_catalog.json`, or point `GRIFFENDO_CATALOG` at a file.
  2. Edit it.
  3. Restart, or use **Rules & channels → Reload catalog & rescan**.

  Invalid rules are skipped and listed on the page. Detections made before the change keep the catalog version they were made under.

## 4. Collector and channels

- **Channels collected.** The launcher now passes `WINLOG_CHANNELS`, which is the original four channels plus the channels that enabled rules need:
  - Defender/Operational
  - WMI-Activity/Operational
  - Sysmon/Operational
  - TaskScheduler/Operational
  - TerminalServices-RemoteConnectionManager/Operational

  PowerShell/Operational is collected only if 4103 or 4104 is enabled.
- **Original channels unchanged.** They are still read in full.
- **Added channels are time-bounded.** They are read only for the last 8 days via an XPath `timediff` filter (`WINLOG_SUPPLEMENTARY_LOOKBACK_HOURS`), so a large Sysmon log doesn't flood the in-memory store.
- **Channel name validation.** Names are checked against a strict pattern because they are embedded in PowerShell. A test confirms an injection attempt is dropped.
- **Per-channel reporting.** The collector now reports each channel's state to a new token-protected endpoint, `/api/collector/status`. The states are:
  - collected
  - empty or disabled
  - not present
  - access denied
  - error
- **Coverage shown in the UI.** The page shows which rules can actually fire. Where retention doesn't reach back 7 days, it shows the coverage as **partial** and gives the real start date.
- **Receiver.** It now accepts the catalog's channels and still rejects anything else.
- **No system changes.** Griffendo does **not** install Sysmon, change audit policy or enable logs.

## 5. UI

The new **Anomalies** item sits between Overview and Event explorer, in the existing visual style. It contains:

- **Severity cards** for the six levels. Each shows detection records and rule-by-host groups, and clicking a card filters the table.
- **Summary cards** for detection records, distinct anomalies, the analysis window and data coverage.
- **Notices** for unmonitored channels, short retention, future-dated events, provider mismatches and status-storage problems.
- **Detections table** with severity, name, rule, Event ID, category, channel and provider, event time, host, user, source address and status.
- **Filters** for search, severity, Event ID, category, channel, host, status and time range (presets or a custom range). They change only what is shown.
- **Grouped view** by rule and host, with drill-down to each occurrence.
- **Rules & channels tab** with per-channel availability and coverage, every rule's monitoring state, and the excluded IDs.
- **Detail dialog** with:
  - the explanation of why the event was flagged
  - a status editor: New, Investigating, Resolved or False Positive, plus a note
  - all detection and event facts
  - the catalog's analyst fields
  - all event data and the rule definition
  - the status history and the original XML

**Changes to existing views are deliberately small:**

- The Event explorer channel filter now lists the added channels.
- Catalog names fill in labels where `EVENT_LABELS` had none; the original 6 labels are unchanged.
- The overview channel list now fits long channel names.
- Auto-refresh also covers the Anomalies page.

## 6. Storage

- **Anomaly records** live in the same in-memory SQLite database as events. This matches the app's existing volatile design.
- **Investigation statuses, notes and history** are written to `%LOCALAPPDATA%\Griffendo\triage.db`, so they survive restarts. When the collector re-sends the same events after a restart, they produce the same detection IDs and their statuses are re-attached. This was verified on the rebuilt exe under Wine.
- **Opting out of disk storage.** Set `GRIFFENDO_STATE_DIR=none` to keep statuses in memory only; the UI then says statuses are not saved.
- **False Positive status** never disables a rule and never deletes an event.

## 7. API additions

| Method & path | Purpose |
|---|---|
| `GET /api/anomalies/summary` | Severity counts, window, coverage, channels, catalog, persistence, last scan |
| `GET /api/anomalies` | Detections. Filters: `severity, event_id, category, channel, host, status, rule_id, since, until, q`. `group=true` returns rule-by-host groups. |
| `GET /api/anomalies/{id}` | Detection detail, evidence, rule, channel status, status history |
| `POST /api/anomalies/{id}/status` | Set status and note. Same-origin only (cross-site requests get 403). |
| `POST /api/anomalies/rescan` | Reload the catalog and re-examine stored events. Same-origin only. |
| `GET /api/anomalies/rules` | All rules with their monitoring state |
| `POST /api/collector/status` | Agent channel report. Bearer token required. |

The existing endpoints are unchanged.

## 8. Files changed

Changed and new files, relative to the reconstructed baseline:

```
src/agent/collector.py        +88   configurable channels, time bound, channel states/report
src/launcher.py               +12   channel list from catalog
src/logplatform/app.py       +127   validation, ingest hook, labels, new endpoints
src/logplatform/anomalies.py +866   new: catalog, engine, window, coverage, triage store
web/app.js / index.html / styles.css   new Anomalies view (+464 total)
catalog/anomaly_catalog.json  new   runtime catalog (also bundled in the exe)
tools/build_catalog.py, build_report.py, repack_exe.py, demo_server.py
tests/ (163 tests), reference/ (your original xlsx)
```

## 9. Tests: what was actually run

**Executed on Linux with CPython 3.12 and the exact bundled library versions: `pytest` 163 passed, 0 failed.** The suite covers:

- **Every rule.** Each of the 116 enabled rules flags a **single bare event** with no data fields, with the correct name, severity and category. Each of the 18 disabled rules flags nothing. Non-catalog IDs flag nothing.
- **Volume and duplicates.**
  - One 4625 is enough.
  - 100 more 4625s give 101 separate records.
  - Re-ingesting plus a rescan creates no duplicates.
  - Two events with the same record ID but different content both survive.
- **Window.**
  - The boundary is exact: start inclusive, start minus 1 second excluded.
  - Within the 5-minute skew tolerance an event is included; beyond it, it is flagged as future-dated.
  - The window rolls forward a day correctly.
  - Missing timestamps fall back to receive time.
  - Windows timestamp formats with 7-digit fractions parse correctly.
- **Channels and providers.**
  - The channel is part of the match: 4625 in Application is not flagged.
  - A provider mismatch is flagged and marked.
  - Unknown channels are rejected by ingest.
  - Channel reports produce the right states and rule-monitoring labels.
  - Partial versus complete coverage is reported correctly.
- **UI behaviour.**
  - Filters don't change detection totals.
  - Statuses persist across an app restart, including the history.
  - False Positive doesn't disable the rule.
  - Invalid statuses and cross-origin writes are refused.
  - The catalog override adds a rule with no code change, and an invalid rule is reported.
- **Spreadsheet.** All 47 spreadsheet rows match the catalog (read from your xlsx).
- **Existing endpoints and auth** are unchanged: `/`, assets, health, overview, events, event detail, processes, timeline, hosts, and 401 on a bad token.
- **Collector, with PowerShell mocked:**
  - channel list and injection rejection
  - the time bound only on added channels
  - error-to-state classification (unavailable, access denied, empty)
  - spool and status report
  - still refuses to run outside Windows

**Rebuilt exe, under Wine 9.0 on Linux:**

- It starts, serves the dashboard, loads the bundled catalog from `_MEIxxxx\catalog\` and creates `triage.db` under LOCALAPPDATA.
- Synthetic ingest produces the expected severity counts (5 / 6 / 4 / 6 / 2 / 1).
- Status changes persist across a full exe restart.
- Collection ran, and because Wine's PowerShell stub returns nothing, every channel was reported as **error**, never as monitored.
- The original exe was run the same way as a control.

**UI:** screenshots were taken with headless Chromium on desktop and at 390 px phone width. There were no console errors and no horizontal scroll.

**Not executed, because these need a real Windows host:**

- Real `Get-WinEvent` collection, including the new XPath time filter.
- Reading the Security log as Administrator.
- Defender, WMI, Sysmon, Task Scheduler and RDP channels with real events.
- SmartScreen or antivirus reaction to the repacked exe.

## 10. Build and packaging

**Rebuild the exe (what produced `dist/Griffendo.exe`).** Run this on any OS with CPython 3.12 and `pip install pyinstaller==6.22.3`:

```
python3.12 tools/build_catalog.py
python3.12 tools/repack_exe.py "path\to\original\Griffendo.exe" dist/Griffendo.exe
```

- **Kept unchanged:** the original bootloader (373,248 bytes, including resources) and every untouched package entry, copied byte-for-byte.
- **Replaced or added:** the PYZ modules `agent.collector`, `logplatform.app` and the new `logplatform.anomalies`; the `launcher` script; the three web files; and the new `catalog\anomaly_catalog.json`.
- **Checks:** the script refuses to run if the bytecode magic or the PyInstaller version differs.
- **Original exe:** SHA-256 `98578d79…97ae42`.

**Alternative: a fresh PyInstaller build on Windows.** This was **not executed**. From the repo root, with the same library versions installed:

```
pyinstaller --onefile --name Griffendo --paths src ^
  --add-data "web;web" --add-data "catalog;catalog" ^
  --hidden-import logplatform.app --hidden-import agent.collector src/launcher.py
```

**Run from source (any OS; collection still needs Windows):**

```
pip install fastapi==0.143.1 uvicorn==0.54.0 pydantic==2.14.1 requests==2.34.2
python src/launcher.py            # or: python tools/demo_server.py  (synthetic data, no Windows needed)
python -m pytest tests
```

## 11. Security notes

- **Defensive and read-only.** The collector only reads event logs. Griffendo never clears, alters or exports logs, never changes system settings, never executes anything remotely, and binds to 127.0.0.1 only.
- **New write endpoints** are same-origin only and validate their input. Channel names passed to PowerShell are allow-list validated.
- **Signing.** The exe is unsigned, as the original was. The repack changes its hash, so treat it like any unsigned internal build. Check `SHA256SUMS.txt` and sign it with your organisation's certificate before distributing it.

## 12. Known limitations and outstanding work

1. **One snapshot per launch.** This is the original design: events logged after launch are not collected until the next start. A periodic re-snapshot is the natural next step, and the ingest-time detection already supports it.
2. **Event store resets on restart.** Events are in memory, as before, so detections are rebuilt from whatever the Windows logs still retain at each launch. Detections for events that have rolled out of the log are lost; only their triage status remains on disk.
3. **Real-Windows validation is outstanding** (see §9).
4. **Many Security rules depend on audit policy.** They need audit subcategories that are off by default, such as Other Object Access for 4698–4702 and MPSSVC Rule-Level Policy Change for 4946–4950. A silent rule may mean "not audited" rather than "didn't happen". The Rules tab lists each rule's prerequisite, but Griffendo cannot read `auditpol` state without new permissions.
5. **Event identity includes the raw XML.** If Windows ever re-renders the same record differently, it would count as a new detection. This hasn't been observed; `ToXml()` output is stable.
6. **Changing a rule doesn't rewrite older detections.** Earlier detections keep their name and severity, recorded with their catalog version.
7. **Duplicate sources are both flagged.** With both Security auditing and the Task Scheduler log on, one task creation yields two detections (4698 and 106), because each event is flagged on its own by design.
