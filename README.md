# Patchboard

A local vulnerability triage notebook built with Python, Flask, SQLite, and ordinary HTML/CSS.

**Question:** How does asset context change a remediation queue compared with severity-only ranking?

The project imports findings, keeps their identity across scans, explains a configurable-in-code priority policy, and records remediation decisions. The comparison page makes the effects of policy weights visible. It does not predict exploitation or claim that its ranking is optimal.

The compact workbench shows priority reasons, observation age, deadlines, rank movement, the latest import, and a readable decision log. Filters cover team owner, state, exposure, exploitation flags, and overdue work; the queue can be sorted by context score, severity, or deadline.

The **Analyst briefing** is a local, rule-generated summary with links to supporting findings. It does not use an AI model, make network requests, or change findings. Whoever runs the app has their own SQLite database on that machine. If deployed on a server later, the database would live on that server instead; this version is intended for local use.

## Hosted demonstration

The public demo is a read-only export with browser-side filtering of synthetic sample findings. It does not run Flask, accept uploads, save decisions, or expose the operator's local database. See [the demo boundary and build instructions](docs/public-demo.md). The full Python application below includes those local workflows.

## Run locally

Requires Python 3.10 or newer. From this folder:

```sh
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```sh
source .venv/bin/activate
```

Then:

```sh
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5050**. Import `data/scan-01.csv` through **Import scan**. The application creates `patchboard.db` beside `app.py`; this runtime database is excluded from version control. Starting with an empty database is intentional, so the import behavior can be inspected.

Do not bind the demo to a public interface. It has no login or multi-user authorization. Its local operator label is not an authenticated identity. The Flask development server is for local exploration.

## Try the investigation

1. Import scan 01. There should be ten findings.
2. Compare `archive-test` with `student-portal`. The first has higher severity; the second has more contextual priority. Read their score components.
3. Mark the portal finding resolved and explain the verification in a note.
4. Import scan 02. The portal finding should reopen because the scanner observed it again. Eleven unique findings should exist, including the new diagnostic endpoint finding.
5. Notice that missing findings remain open. These CSV files do not certify complete scan coverage.
6. Record an exception with a reason and an expiry within 90 days. It leaves the actionable queue until the day after its expiry date.
7. Visit **Ranking study**. Compare the default, zero-exposure-weight, and double-exploitation-weight policies.

All assets, findings, scanner labels, and exploitation flags in the samples are invented. `LAB-001` and similar labels are not CVE identifiers. Dates belong to the fictional scan case, not to the project's development history.

## Verify

```sh
python -m unittest discover -s tests -v
python evaluate.py
```

`triage.py`, its tests, and the evaluation script use only Python's standard library. Web integration tests require Flask and explicitly skip when it is missing. A skipped test is not a passing web verification.

See [verification notes](docs/verification.md) for the checks actually performed in the creation environment.

## Design decisions

- **SQLite, one operator:** enough to investigate transactional imports without adding a database service. Each web operation closes its connection.
- **Asset + vulnerability identity:** repeat observations update existing findings. This assumes scanner identifiers and asset names are stable. Separate instances on different ports are not modeled yet.
- **Whole-batch validation:** a broken CSV does not leave a half-imported queue. Duplicate pairs and inconsistent metadata are rejected, with row-level validation messages.
- **Explainable arithmetic:** every default score is the sum of four visible terms. The weights are policy assumptions, not learned parameters.
- **Conservative lifecycle:** a repeated observation reopens a resolved finding; a missing observation cannot resolve one. Import history records each accepted batch.
- **No live enrichment yet:** exploitation flags are supplied by the CSV. An external feed integration needs source timestamps, matching rules, and stale-data handling before it belongs in this model.

## Study and limitations

Read [the study protocol](docs/study.md), [architecture and threat model](docs/design.md), and [the walkthrough](docs/walkthrough.md).

This is a working research prototype, not a completed graduate research result. A stronger evaluation needs independently reviewed priorities, more scenarios, alternative scoring models, and uncertainty analysis. The present synthetic comparison is deliberately limited to reproducible ranking behavior.

The application and initial sample materials were developed with AI assistance. Before presenting the project, run it, inspect the implementation, and record your own experiments and design decisions. Do not claim experiments or operational use that have not happened.
