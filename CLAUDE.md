# Working on TRACELOG

TRACELOG is the adapter layer between perimeter log sources and SIEMs: it receives logs from
firewalls, IDS/IPS, VPN gateways and proxies, archives every line byte-for-byte, parses it,
normalises it to OCSF 1.1.0, links it into a hash chain and forwards it to whatever the SOC runs.
Built for SIH 2026, problem statement 26156 (NTRO).

`README.md` is the overview. `docs/PARSING.md` explains the four-tier parser, `docs/PERFORMANCE.md`
what was optimised and what the numbers are, `docs/RUNBOOK.md` how to install, run and measure on a
fresh machine, `docs/CONNECTORS.md` the inputs and outputs.

## The rules this project is built on

**Never print a number the code did not measure.** Every figure on the dashboard comes from the
database or the running server. If three events arrived and one was read by a vendor pack, the card
says 33.3 %. A constant standing in for a measurement — an accuracy, a confidence, a throughput —
is the one thing that would discredit everything else here. (`backend/services/correlation/engine.py`
still has hardcoded confidence scores. That is a known defect, not a pattern to copy.)

**A missing field beats a wrong field.** The generic parser fills a field only when there is
evidence for what the field means *and* that its value is valid; two addresses with nothing saying
which is the source stay unassigned. The measured score is 85 correct, 18 missed, **0 wrong** over
103 fields in 13 formats no pack knows. Any change that lifts "correct" by making "wrong" non-zero
is a regression, whatever the totals say.

**Nothing received is ever lost or rewritten.** Lines that fail to parse are still archived, hashed
and chained as OCSF Base Events. A re-parse never edits an event: the original stays in the chain
and the new version is appended, linked by `supersedes`, with `superseded_by` as an index over it.

**The hashed record is frozen.** `H(prev : seq : raw_hash : canonical_json)` with canonical JSON
(sorted keys, compact separators, UTF-8). Changing what goes into the preimage invalidates every
existing chain, so it is a versioned decision, never a side effect of a refactor.
`tests/test_throughput.py` guards this.

## Before you say something works

```bash
pytest -q                                   # 147 passing
python scripts/evaluate_unseen_formats.py   # 85 correct, 18 missed, 0 WRONG
python scripts/benchmark.py -n 20000 -b 1000 --read
```

Those three are the project's own acceptance test. The benchmark is also how any performance claim
gets made: measured, on stated hardware, with the script in the repo. On a 2-core box it reports
about 2,700 events/s single process and 4,866 with `-w 2`. Quote a rate with its hardware beside
it, and never a round number that no run produced.

## House style

Code carries its reasoning. Module docstrings say what the module is for and why it works the way
it does; comments explain the decision, not the syntax. Prose is plain — write "the chain head is
read once per batch", not "leverages optimised head retrieval". No marketing adjectives in code,
docs or commit messages.

Commit messages: one imperative line saying what changed, then the reasoning and the measured
effect. Look at the recent history for the shape. End every commit with:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```

Create new commits; never rewrite published history and never skip hooks.

## Things that must not happen

- `.env` is never committed. Secrets come from the environment; config files reference `${VAR}`.
  Never hardcode a token or ask anyone to paste one into a file.
- The third-party vendor sample corpus (Elastic integrations fixtures) is **not** committed — it is
  Elastic-licensed. Fetch it when scoring, keep it out of git.
- `Claude outputs/` is the user's own folder. Do not commit it, do not delete it.
- Ask before deleting any of the user's files, including the leftover test YAMLs in `core/plugins`.
- The legacy parallel app was archived on branch `archive/legacy-app`. Do not resurrect it.

## Where things live

```
backend/api/           FastAPI routes
backend/connectors/    inputs (syslog, HTTP, file tail, Kafka) and 15 output sinks, engine, dead letters
backend/services/
  parsing/             dispatch, vendor-pack detection, the evidence-based generic parser, the format registry
  vendors/             one module per vendor pack
  parser_generation/   learning a parser from samples, approval, re-parsing history as chained revisions
  normalization/       OCSF normaliser, strict export, validator
  integrity/           hasher, chain ledger, reconciliation, audit report
  ingestion/           the batch writer (stream.py) and the single-line path (pipeline.py)
  storage/             SQLite schema, migrations, indexes
frontend/              Streamlit dashboard, one module per page
scripts/               benchmark, unseen-format scoring, sample sender, connector docs
tests/                 147 tests; conftest.py gives every test an isolated database
```

`backend/services/ingestion/stream.py` is the hot path: one transaction per batch, the chain head
read once and carried in memory, rows written with `executemany`. Read `docs/PERFORMANCE.md` before
changing anything in it.

## Known gaps, if you are looking for work

Ranked in `Claude outputs/TRACELOG-status-and-plan.md`. The short list: no API authentication or
CORS restriction; the tamper endpoint is open; Kafka commits offsets before the batch is stored; the
Parquet sink's paths are not Security Lake's layout; Snort's CSV, JSON and full alert formats are
unhandled; services that run on a firewall host (DHCP, IPsec, DNS, proxies) have no packs, which is
also the natural place to add OCSF classes 4002, 4003 and 4004; the RCA page's confidence scores are
constants.
