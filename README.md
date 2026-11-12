# dsiem + Griffendo

This repository holds two independent projects side by side. They are kept as
separate, self-contained codebases so that each one can still be built, tested
and run on its own.

| Directory    | Project                                  | Language | What it does |
|--------------|------------------------------------------|----------|--------------|
| [`dsiem/`](dsiem/)       | Dsiem — correlation engine   | Go (1.23, vendored deps) | OSSIM-style directive/correlation engine for ELK. Consumes normalised events, applies directive rules (including cross-event, time-windowed correlation), and raises risk-adjusted alarms. |
| [`griffendo/`](griffendo/) | Griffendo v5.1 — Windows event intelligence | Python 3.11 (FastAPI + web dashboard) | Collects Windows Event Log / Sysmon events, matches them against a rule inventory, correlates multi-step activity, scores risk and raises alerts by severity. |

The goal of putting them in one repository is to **bring dsiem's correlation
logic into Griffendo**, so the plan is to work on them here while keeping the
two trees independently runnable.

---

## dsiem/

The original Dsiem source, unchanged apart from being moved into `dsiem/`.

```bash
cd dsiem
go build ./cmd/...                  # uses the vendored dependency tree
go test ./...
```

See [`dsiem/README.md`](dsiem/README.md) for the full documentation (configs,
directives, clustering with NATS, threat-intel plugins, web UI, Docker demo).

Key places for the correlation work:

- `dsiem/internal/pkg/dsiem/` — the engine: directive handling, event
  correlation, alarm generation.
- `dsiem/configs/` — directive and config examples.
- `dsiem/cmd/dsiem/` — the server entrypoint.

## griffendo/

The Griffendo v5.1 sources, extracted from `Griffendo_v5.1_source.zip`.

```bash
cd griffendo
python -m pytest tests              # synthetic events, no Windows required
python tools/demo_server.py         # dashboard + collector against a synthetic live log
```

Requirements: Python 3.11 with `fastapi`, `pydantic`, `uvicorn`, `requests`,
`openpyxl` (and `httpx` + `pytest` for the test suite). See
[`griffendo/README.md`](griffendo/README.md) for the environment variables,
engine settings and the report describing the v5.1 detection engine.

Key places for the correlation work:

- `griffendo/src/logplatform/detection/engine/` — detection/correlation engine
  (`matcher.py`, `aggregator.py`, `chain.py`, `behavior.py`, `decision.py`).
- `griffendo/src/logplatform/detection/rules/` — one Python file per rule,
  loaded through `rules/index.py`.
- `griffendo/src/agent/` — the Windows event collector.
- `griffendo/catalog/anomaly_catalog.json` — the built-in rule catalogue.

---

## CI

Continuous integration for dsiem lives at the repository root (`.github/`,
`.circleci/`) because those are the only locations the providers read. The
workflows are configured with `working-directory: dsiem` and reference
`dsiem/go.mod`, so they keep building and testing the Go project from its
new location. Griffendo's tests are run directly with `pytest` from
`griffendo/`.
