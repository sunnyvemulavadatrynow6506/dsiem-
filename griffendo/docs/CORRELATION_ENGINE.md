# Griffendo v6 — Correlation Engine and Capability Report

This document describes the redevelopment of Griffendo's detection and correlation
capability, the parts of DSIEM that informed it, and — just as importantly — the parts
that were deliberately **not** adopted. It is written for two readers: someone with
basic IT knowledge who needs to understand what the product does and what it can see,
and a developer who needs to change it without re-deriving the design.

Companion documents: `docs/REPORT.md` (v5.1), `docs/REPORT_v2.md` … `docs/REPORT_v4.md`
(history), `README.md` (settings reference).

---

## 1. What Griffendo is

Griffendo is a **single-endpoint** Windows security monitor. It reads Windows Event Log
channels (and Sysmon, when installed), normalises each record, matches it against a rule
inventory, correlates related activity into detections, scores the risk, and presents an
investigation view in a local web UI.

Its defining constraint is the one that shapes every decision below: **it runs on the
endpoint it monitors, with no central collection tier, no Elasticsearch, no external
enrichment service, and no cloud**. Everything is SQLite plus a FastAPI process plus a
browser.

---

## 2. The defect that motivated this work

Before the redevelopment, the correlation layer grouped signals into a **fixed 30-minute
bucket per entity**. A "signal" was a single rule match; a detection was the set of
signals that landed in the same bucket for the same user/logon/process.

That design has three structural consequences, and all three were measurable:

| Consequence | Measurement on the v5.1 synthetic corpus (7 days, 6,034 events, 345 rules) |
|---|---|
| One detection per matching event | 279 detections from 347 signals; 112 of them were a **single** failed logon |
| Repetition is invisible | 40 failed logons from one address and 1 typo produced the *same* detection and the same score |
| A live incident splits at every bucket boundary | an attack spanning 30+ minutes became several unrelated detections |

The engine was not "broken" in the sense of crashing; it produced output. It was broken in
the sense that its output could not answer the only questions an analyst has: *is this one
incident?*, *how much of it is there?*, and *why is it rated this high?*

Notably, 48 of 279 detections *did* contain more than one signal, so correlation was not
entirely absent — it was just too coarse in one direction (everything one user did in half
an hour) and too fine in the other (a series reset at the boundary).

---

## 3. What DSIEM does, and what was learned from it

DSIEM is a different shape of product: a horizontally scalable OSSIM-style correlation
engine for an ELK stack, with directives shipped over NATS. Reading its implementation
(rather than its UI) produced a short list of mechanisms that are genuinely transferable
to a single endpoint, and a longer list that depends on infrastructure Griffendo does not
have.

### 3.1 The one mechanism that mattered: the backlog

`internal/pkg/dsiem/siem/backlog.go` and `backlogmgr.go` implement the core idea.
A **backlog** is a correlation context bound to an entity (a source/destination pair).
Events are pushed into every backlog of the directive that could match them. Inside the
backlog:

- each rule has a `stage`, an `occurrence` count and a `timeout`;
- a rule accumulates matching events; when the stage reaches `occurrence` the rule is
  "finished" (`processMatchedEvent`), risk is recomputed, and the stage advances;
- `expirationChecker` expires a backlog whose rules have not been satisfied within
  `timeout`, so the directive stops waiting;
- when the last stage reaches its occurrence the alarm is written and the backlog is
  deleted.

The important consequences are that **one correlation context produces one alarm, however
many events filled it**, and that **repetition is a first-class part of the rule** (via
`occurrence`), not an afterthought.

### 3.2 Transferred too: directive stages

A DSIEM directive is an ordered list of rules, each with a `stage`, an `occurrence`, a
`timeout` and a **`reliability`** (`internal/pkg/dsiem/siem/directive.go`). As a backlog
fills, `increaseStage()` walks the rule list upward: the same alarm is re-scored with a
higher reliability instead of a second alarm being created. The alarm's risk is

```
risk = priority * reliability * assetValue / 25      # alarm.calcRisk, clamped 0-10
```

classified Low / Medium / High by the directive's `medium_lower` / `medium_upper` bounds.

This is now replicated in `correlation/stages.py` (see §4.6), because it is the one part of
DSIEM's model that expresses *escalation over time* and the v6 engine's flat occurrence
escalation could not: a lone failure and a 10 000-attempt brute force reached the same
stage-less score. Stage reliability maps onto Griffendo's 0-100 scale as
`score = reliability * 10` (derived from the formula above with priority 10, asset 5, then
rescaled ×5), and the reached stage's score replaces the rule's flat score before the
noisy-OR runs, so staging changes the number the analyst sees and not just the text.

### 3.3 Also transferred: de-duplication by identity

DSIEM identifies a backlog by its entity, and an alarm by the backlog id
(`findOrCreateAlarm(id)`), so re-processing the same activity updates an alarm instead of
creating a second one. The v6 engine does the same with a **deterministic episode id**
derived from the correlation key and the time bucket, which is what makes replay and
re-evaluation idempotent.

### 3.4 Read, understood, and deliberately **not** transferred

These are all real DSIEM capabilities. Each was evaluated against Griffendo's architecture
and rejected for a stated reason — not because it was hard, but because it either needs
infrastructure Griffendo does not have or would duplicate something that already works.

| DSIEM capability | Where it lives | Why it was not adopted |
|---|---|---|
| Threat-intel enrichment (Arkime Wise, OTX) | `xcorrelator/intel.go` | Requires outbound lookups to third-party services. An endpoint agent should not depend on internet reachability or silently exfiltrate indicators. Future: an offline, analyst-supplied indicator list. |
| Vulnerability enrichment (Nessus CSV) | `xcorrelator/vuln.go`, `cmd/ossimcnv` | Needs a vulnerability scanner's export. Griffendo has no asset/vulnerability inventory and an endpoint cannot infer one. |
| Asset importance weighting | `internal/pkg/dsiem/asset/asset.go` | DSIEM weights risk by a curated CIDR→value map because it defends a *network*. Griffendo already has the endpoint-scoped equivalent (`GRIFFENDO_CRITICAL_ASSET`), which is the correct granularity for one host. |
| NATS clustering (`vice`), backpressure, rate limiting | `internal/pkg/dsiem/vice`, `limiter`, `queue` | Griffendo is one process on one host. There is nothing to distribute, and the collector already has backpressure. |
| Elasticsearch alarm storage and Kibana pivot | `alarm/helper.go` | SQLite is the right store for a local agent; the UI provides the pivot directly. |
| OSSIM directive XML + taxonomy conversion | `cmd/ossimcnv`, `dpluger` | Griffendo already imports Elastic and Wazuh rule sets (`tools/rules_import`), which are the live formats. OSSIM XML would add a translation layer for a product Griffendo does not interoperate with. |
| `sticky_different` (suppress repeats of an identical value) | `rule/rule.go` `SDiffString` | Superseded by two stronger v5 mechanisms that were kept: rule *suppression* by exact fingerprint (`decision.py`) and *new terms* / first-seen detection. A sticky-value list is a weaker version of both and would add a third, conflicting suppression path. |
| Alarms as the unit of record, with status/tag editing in Kibana | `alarm/`, `web/ui` | Griffendo's detection is the unit, and it is already richer: evidence events, contributing rules, per-rule condition explanations, analyst status, verdicts, notes and suppression history. |
| Plugin/SID rule inputs from OSSIM sensors | `rule/rule.go` `QuickCheckPluginRule` | Griffendo's inputs are Windows event IDs and ECS fields, not sensor plugin IDs. The equivalent fast pre-filter already exists (`Registry.candidates(channel, event_id)`). |

---

## 4. The v6 engine

### 4.1 Pipeline

```
raw event  ->  normalise  ->  rule match (v5 matchers, unchanged)
                            ->  classify      identity + occurrence policy   correlation/identity.py
                            ->  occurrence    has this rule fired yet?       correlation/state.py
                            ->  place         which open episode?            correlation/engine.py
                            ->  stages        DSIEM directive stages         correlation/stages.py
                            ->  score         noisy-OR + escalation          correlation/risk.py
                            ->  aggregate     episode row + counters         correlation/aggregator.py
                            ->  store / API / UI                             engine/store.py, queries.py
```

Every stage is a separate module with a single responsibility. The vintage v5 matchers
(Elastic EQL/KQL translations, Wazuh trees, chain correlator, behaviour model) are
**reused unchanged**: they answer "does this event match this rule", which they do well.
What was replaced is everything *after* that question.

### 4.2 Identity: what "the same thing" means

Two keys are derived from event content only (never from arrival order, so replay is
reproducible):

- **entity key** — the actor: logon session → user → process GUID → host. System accounts
  (`SYSTEM`, `LOCAL SERVICE`) and system logon sessions are excluded, exactly as in v5,
  because they would join unrelated activity.
- **correlation key** — the *subject*, which keeps independent incidents apart:
  - authentication events → `entity|auth|<account>|<source address>`. Brute force from one
    address is one incident; the same account logging in locally is another.
  - process-scoped events → `entity|proc|<root of the process tree>`. Two unrelated command
    lines run by the same administrator are not one detection.
  - everything else → the entity alone.

This mirrors DSIEM's choice of backlog identity (a directive-bound entity pair) rather
than "everything this user did in the window".

### 4.3 Occurrence and timeout

`correlation/state.py` implements DSIEM's `occurrence` + `timeout` as an explicit,
tested state machine:

```python
observe(rule_id, key, t, required, timeout, escalate, event) -> Observation
```

- **`required` (occurrence)** — the rule does not emit until the series holds N matches.
  A rule with `occurrence: 5` yields one detection carrying five events.
- **`timeout`** — a match arriving later than the timeout after the previous one starts a
  new series (count restarts). This is the backlog-expiry behaviour.
- **`escalate`** — opt-in per rule. Non-escalating rules report their true occurrence
  count but keep their risk at the required count, so a burst is *visible* without
  becoming arbitrarily dangerous. Escalating rules grow, and the escalation curve is
  bounded (§4.5).

Distinct counters are kept deliberately: `count` is the true number of occurrences (what
the analyst sees) and `risk_count` is what the scorer may use.

### 4.4 Episodes (the replacement for buckets)

An **episode** is the v6 equivalent of a backlog: one detection that stays open while
evidence keeps arriving for the same correlation key. Placement (`engine.place`):

1. if an episode is open for this correlation key and the gap since its last evidence is
   within the rule's timeout, the match joins **that episode** — even across a bucket
   boundary, so a multi-hour incident stays one incident;
2. otherwise a new episode opens in the event's own fixed time bucket.

The episode id is `sha256(correlation_key | bucket)` truncated to 32 hex characters. Because
it is a pure function of content, replaying history, re-evaluating a rule and processing
live events all converge on the same rows.

Evidence is always kept: every match is a signal row holding the events that produced it
(capped at 25 per signal, with the newest retained), and the episode references its
signals. Nothing is discarded on suppression, retraction or rule change.

### 4.5 Risk scoring

The v5 scorer (`engine/risk.py`) is reused, because its core is sound:

```
score = max(strongest signal, 100 * (1 - prod(1 - w_i * s_i * decay_i)))
```

over **distinct rules only** (strongest signal per rule), skipping signals whose evidence
events a stronger signal already counted, with a half-life decay (`GRIFFENDO_SIGNAL_HALF_LIFE_MINUTES`,
default 15). That prevents the same event matched by three rules from being counted as
three independent findings.

What v6 adds (`correlation/risk.py`) is the one thing that model structurally cannot see —
repetition:

```
escalation = min(cap, per_decade * log10(occurrences))      # only for rules that opt in
episode_score = min(100, noisy_OR_score + escalation)
```

Defaults: `per_decade = 4`, `cap = 12`. Ten occurrences add 4 points, a hundred add 8, a
thousand add 12 — a logarithmic curve, so volume is meaningful but never dominant, and the
cap means escalation alone cannot promote a Low finding to Critical.

Every component is returned with the score (`base_score`, `escalation.applied`, per-rule
occurrence counts) and rendered in the UI, so the number is auditable rather than mystical:

> *Score 30/100 from Failed logon (30, decayed ×0.908). … Repetition adds 5.5 points
> (bounded at 12, logarithmic: SEC-4625 ×24 (+5.5)), so this detection scores 36/100
> instead of 30.*

Severity bands remain configurable (`GRIFFENDO_SEVERITY_THRESHOLDS`, default `90,70,40,20`).

### 4.6 Rule authoring: the `correlation` block

A rule opts into occurrence semantics with one optional block; no engine change is needed
to add a rule:

```python
'correlation': {
    'occurrence': 5,          # emit only on the 5th match of a series
    'timeout_seconds': 600,   # a gap longer than this starts a new series
    'escalate': True,         # let repetition raise the score (bounded)
}
```

Absent, the defaults apply (`occurrence: 1`, `timeout: GRIFFENDO_CORRELATION_TIMEOUT_SECONDS`,
no escalation, no stages), so rules that do not opt in keep their exact previous behaviour.

**Stages** (DSIEM directives) are a second, optional block. They say how an indicator's
reliability grows as the series accumulates:

```python
'correlation': {
    'stages': [
        {'occurrence': 1,   'timeout_seconds': 300,  'reliability': 1},   # stage 1: one match
        {'occurrence': 10,  'timeout_seconds': 3600, 'reliability': 6},   # stage 2: ten matches
        {'occurrence': 100, 'timeout_seconds': 7200, 'reliability': 9},   # stage 3: a hundred
    ],
}
```

The block is validated when the rule loads (`registry.validate_spec`), not at scoring time,
so a bad stage is reported against the rule file with an actionable message: 1-10 stages,
non-decreasing `occurrence`, stage 1 must have `occurrence: 1` (otherwise the rule could
never alert), `reliability` 1-10, `timeout_seconds` 1 s - 7 days.

Semantics, and the one deliberate deviation:

- `occurrence` is **cumulative** (total matches in the series), whereas DSIEM counts
  occurrences per stage. The port is equivalent because a backlog keeps all of its events,
  so DSIEM's per-stage counts also accumulate — but cumulative counts are what an analyst
  can check against the occurrence counter in the UI. This is the only deviation.
- the reached stage's score is `reliability * 10`, and it *replaces* the rule's flat score
  before correlation (`risk.staged`), so a stage-3 burst really scores higher. The pre-stage
  score is kept in `contributors[].base_rule_score` and the stage fields (`stage`,
  `stages`, `reached_at`, `reliability`, `score`, `expired`, `next_occurrence`) are stored on
  the episode and exposed by the API.
- a stage that waits past its `timeout_seconds` without reaching the next stage is marked
  `expired`: the evidence is kept and the explanation says so. The series itself restarts
  under the ordinary `timeout_seconds` rule (§4.3).
- the ``escalate`` bonus still applies on top of the stage score, but it is additive and
  bounded (12), so it can refine a stage's rating rather than override it.

`SEC-4625` (failed logon) is the first rule to opt in, to **both** mechanisms, because
repetition is precisely what distinguishes brute force from a typo: occurrence escalation
raises the score smoothly, and stages 1/2/3 (reliability 1/6/9 at 1/10/100 matches) give the
analyst DSIEM's reliability view of the same episode.

### 4.7 Determinism, replay and re-evaluation

- **Replay after restart** rebuilds process, logon and occurrence state from stored events
  over the longest correlation horizon (`_max_window` now includes rule timeouts and two
  buckets), so a running series resumes instead of restarting its count.
- **Re-evaluation** (rule switched on or edited) runs through the same correlation bridge
  as live processing. This was a real defect found during this work: it used to bypass the
  correlator, so one off/on cycle re-created 100+ single-event detections. Verified fixed:
  114 detections before an off/on cycle, 114 after.
- **Retraction** keeps evidence: a re-evaluation retracts its own previous signals
  (`decision='retracted'`, rows retained) and revives a retracted signal whose evidence
  matches again, rather than duplicating it. Live-collected signals are never touched.

---

## 5. Process lineage (monitoring improvement)

The Process page previously inferred parent-child links from one normalised parent name
and grouped process *names*; an exact Sysmon GUID link and a PID-only 4688 link looked the
same.

`GET /api/process-lineage` now builds real nodes and edges from stored process-creation
events and states the strength of every edge:

- **exact** — Sysmon Event ID 1 `ParentProcessGuid`: an identity, immune to PID reuse;
- **probable** — Security 4688 `ProcessId`: a PID, which *can* be reused, so the link is
  probable and labelled as such.

The response includes per-node command line, user, host, execution count and the source
channel, plus totals and an explicit caveat. Nothing the telemetry cannot prove is
emitted. On the synthetic corpus the attack chain renders as one tree:
`WINWORD.EXE → powershell.exe (-enc) → schtasks.exe (/create)`.

---

## 6. Storage and migration

New columns on `det_signals` (`correlation_key`, `occurrences`, `episode_bucket`,
`expires_at`) and `det_detections` (`correlation_key`, `episode_bucket`, `base_score`,
`escalation_json`, `occurrence_count`, `source_mix`, `assigned_to`, `stage_json`).

`store.migrate()` adds missing columns with `ALTER TABLE` on start-up — idempotent, no data
loss, no table rewrite. `store.backfill_v6()` fills the new columns for pre-v6 rows from
data those rows already hold and **preserves the historical score** (it was shown to
analysts at the time; recomputing it would rewrite history). Pre-v6 detections are marked
`source_mix = ["legacy-v5"]` so the provenance is visible.

---

## 7. Telemetry reality check

Griffendo can only detect what the host actually logs. This is stated in the product
rather than assumed:

| Capability | Data source | Available by default? | If missing |
|---|---|---|---|
| Failed/successful logon, lockout, account changes | Security 4624/4625/4740/4720… | **No** — requires *Audit Logon* / *Audit Account Management* | Detection is silent; the rule cannot match |
| Process creation | Security 4688 | **No** — requires *Audit Process Creation* (and command-line inclusion) | Use Sysmon Event 1 |
| Process lineage (exact) | Sysmon Event 1 GUIDs | Only with Sysmon | 4688 gives PID-only *probable* links |
| File create/delete/modify | Sysmon 11/23/26, 2, 15 | Only with Sysmon (+ SACL for 4663) | Windows does not log file operations by default |
| Registry changes | Sysmon 12/13/14 | Only with Sysmon (or registry SACL auditing) | Not visible |
| Network connections | Sysmon 3, DNS 22 | Only with Sysmon | Security logs do not contain connections |
| Service install | System 7045 / Security 4697 | 7045 usually present | Depends on audit policy |
| Scheduled tasks | Security 4698 / TaskScheduler 106 | Needs *Audit Other Object Access* | Partially visible |
| PowerShell script blocks | PowerShell 4104 | Needs *Script Block Logging* | Command line only (4688/Sysmon 1) |

The rules that need an optional source are already tagged (`support.status =
requires_optional_source`) and the UI shows support status per rule, so an operator can see
*why* a rule is quiet instead of assuming it is working.

---

## 8. Testing

| Suite | What it protects |
|---|---|
| `tests/test_correlation_engine.py` (23) | bucket purity, identity separation (system accounts, auth account+source, process tree), occurrence requirement, occurrence after the requirement, timeout series reset, parallel vs escalating counts, bounded state, escalation curve and cap, opt-in escalation, corroboration, same-event double-counting, **stage validation, stage escalation, stage expiry, stage score replacing the rule score** |
| `tests/test_correlation_integration.py` (13) | end-to-end through the real receiver: 40 logons → **1** detection with 40 occurrences; distinct incidents not merged; isolated events days apart stay separate; escalation raises score and the explanation says why; dashboard counts equal stored records; evidence links to events; analyst status survives new evidence; threshold does not go silent; true negative produces no detection; exact vs probable lineage; **a staged rule walking stage 1 → 3 on one episode** |
| existing suites (71) | v5 behaviour preserved: matchers, conditions, normalizer, Wazuh tree, chain correlator, behaviour model, API, collection, startup |

**Total: 107 passing.** The suites are run with `python -m pytest tests`.

---

## 9. Configuration added

| Variable | Default | Meaning |
|---|---|---|
| `GRIFFENDO_CORRELATION_BUCKET_MINUTES` | `30` | Episode bucket width |
| `GRIFFENDO_CORRELATION_TIMEOUT_SECONDS` | `300` | Default series timeout when a rule sets none |
| `GRIFFENDO_CORRELATION_MAX_SERIES` | `100000` | Bound on in-memory occurrence series |
| `GRIFFENDO_CORRELATION_MAX_SIGNALS` | `2000` | Safety valve on signals per episode |
| `GRIFFENDO_RISK_OCCURRENCE_ESCALATION` | `1` | Master switch for escalation |
| `GRIFFENDO_RISK_OCCURRENCE_MAX` | `12` | Escalation cap (points) |
| `GRIFFENDO_RISK_ESCALATION_PER_DECADE` | `4` | Points per 10× occurrences |
| `GRIFFENDO_SUPPRESSION` | `1` | Enable fingerprint suppression |

---

## 10. Remaining limitations, stated plainly

1. **The occurrence state is in memory.** It is rebuilt by replay after a restart, which
   is correct but costs a replay of the correlation window. Persisting it is a future
   optimisation, not a correctness fix.
2. **Escalation and stages are opt-in per rule, and today only `SEC-4625` opts in to
   both.** That is deliberate: escalation should be a considered decision per indicator,
   not a global multiplier. Extending it to other volume-shaped rules (4776, 4625 variants, error
   bursts) is a follow-up that needs a false-positive pass on real data.
3. **Correlation is per host.** A lateral-movement chain that spans two machines cannot be
   correlated, because Griffendo has no cross-endpoint store. Adding one would be a
   different product (and is exactly the DSIEM/ELK role that was excluded).
4. **Behaviour-model interaction is unchanged.** Behaviour signals pass through the
   correlator untouched; they were already aggregated by the model, and their
   learn/shadow/active lifecycle is orthogonal to occurrence.
5. **Suppression is fingerprint-based** (same rule + same activity fingerprint). A
   materially different event still alerts; this is the v5 behaviour and was kept because
   it is the safer default.
6. **The UI was verified through its data contracts and render functions, not a real
   browser** in this environment (no browser could be installed). The JS parses, is
   exercised in Node against live API payloads, and the endpoints it consumes return
   verified data — but a human should still click through once on Windows.

---

## 11. File map

**Added**

```
src/logplatform/detection/correlation/__init__.py      package doc + pipeline diagram
src/logplatform/detection/correlation/config.py       all tunables, env-driven
src/logplatform/detection/correlation/identity.py     entity / correlation keys
src/logplatform/detection/correlation/buckets.py      pure time buckets
src/logplatform/detection/correlation/state.py        occurrence + timeout state machine
src/logplatform/detection/correlation/risk.py         noisy-OR + bounded escalation + staging
src/logplatform/detection/correlation/stages.py       DSIEM directive stages (validate/evaluate/explain)
src/logplatform/detection/correlation/engine.py       classify/observe/place/build
src/logplatform/detection/correlation/aggregator.py   EpisodeAggregator (persist/recompute)
tests/test_correlation_engine.py                      23 unit tests
tests/test_correlation_integration.py                 13 end-to-end tests
docs/CORRELATION_ENGINE.md                            this document
```

**Modified**

```
src/logplatform/detection/engine/service.py    correlator wiring, correlate bridge, re-eval fix
src/logplatform/detection/engine/store.py      v6 columns (incl. stage_json), migrate(), backfill_v6()
src/logplatform/detection/engine/registry.py   stage validation at load + stage summary in the API
src/logplatform/detection/engine/queries.py    v6 fields, scope label, new sorts
src/logplatform/app.py                         /api/process-lineage
src/logplatform/detection_api.py               sort enum
src/logplatform/detection/rules/windows/security/rule_SEC_4625.py   correlation block
web/detections.js                              occurrence/escalation/stage display
web/app.js                                     lineage renderer
web/index.html                                 lineage surface
web/styles.css                                 lineage + escalation styles
```

**Replaced (kept for reference in git history, no longer imported)**

```
src/logplatform/detection/engine/aggregator.py   v5 fixed-bucket Aggregator
```

---

## 12. How to run

```bash
cd griffendo
python -m pytest tests                 # 107 tests, synthetic events, no Windows needed
python tools/demo_server.py 8765       # dashboard + collector against a synthetic live log
python src/launcher.py                 # the real agent on Windows (see griffendo/README.md)
```

Requirements: Python 3.11 with `fastapi`, `pydantic`, `uvicorn`, `requests`, `openpyxl`
(`pytest` and `httpx` for the suite).
