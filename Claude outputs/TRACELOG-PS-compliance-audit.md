# TRACELOG against PS 26156 — requirement by requirement, with proof

Checked on 24 September 2026 against `main` at `df3bb3b` (172 tests). Every verdict below rests on
something that was run today — a probe, a test, or a measured number — not on what the code is
supposed to do. The Kafka offset fix and the pfSense service packs with OCSF classes 4002/4003/4004
are already planned and are left out of the gap lists.

Verdicts: **Proven** (evidence a judge can rerun), **Partial** (works, with a demonstrated defect or
hole), **Not proven** (nothing in the project shows it).

---

## Expected solutions (a)–(k)

| # | The PS asks | Verdict | Proof found | What is lacking |
|---|---|---|---|---|
| a | Preserve complete raw event data without information loss | **Partial — defect proven** | Streamed lines are stored so the original bytes can be rebuilt (`raw_text` + `raw_encoding`); lines that fail to parse are still archived and chained. | **File upload destroys bytes:** a line with `caf\xe9` is stored as `caf�` — `decode("utf-8", errors="replace")` in `backend/api/ingestion.py`. **The single-line API strips whitespace** (`pipeline.py`, `.strip()`). **For non-UTF-8 lines the stored SHA-256 is of the UTF-8 re-encoding, not of the bytes received** — probe: hash matches the received bytes for UTF-8 lines, does not for `\xe9` or `\xff\xfe`. |
| b | Extract and parse source-specific attributes | **Proven** | 11 vendor packs + CEF/LEEF; vendor field names kept in `vendor_fields`; **91.9 % of 2,356 third-party vendor sample lines read by a pack, 0 crashes**; `tests/test_vendor_packs.py`, `tests/test_snort_formats.py`. | Perimeter devices in scope with no pack, probed today: **Cisco IOS router ACL logs** (Network Activity, but no addresses extracted), **ModSecurity WAF** (Base Event, nothing extracted). No wrong fields — just nothing. |
| c | Normalize fields into a common event taxonomy | **Proven** | OCSF with a strict export and validator; **0 OCSF-invalid events** across the third-party corpus; version choice recorded in `docs/adr/0001-ocsf-version.md`; `tests/test_ocsf_version.py`. | Only four classes (planned additions excluded here). WAF logs land as Base Event. |
| d | Maintain traceability between normalized and original events | **Proven** | Probe: **5/5 exported OCSF events resolve through `/api/events/{uid}` to their raw line, whose SHA-256 matches, with a chain record.** Re-parse revisions link to what they supersede (`tests/test_format_learning.py`); delivery ledger and reconciliation. | The chain is unsigned and not anchored anywhere outside the database (see theme, below). |
| e | Plug-and-play onboarding of new log sources | **Proven** | Devices auto-register by hostname, even behind relays; setup guides for 11 vendors and 6 forwarders; unknown formats surface in Parser Studio and a learned parser goes live without a restart. | Adding or changing an **output** needs a YAML edit and a restart — there is no API for it. Minor; the PS says *sources*. |
| f | Unified visibility across enterprise environments | **Partial** | One OCSF shape across every source; Overview, Pipeline, Explorer and Schema pages are measured from the database. | **The Correlation & RCA page shows invented confidence scores** — 0.88, 0.92, 0.85, 0.89/0.75, 0.80/0.65, 0.60 are constants in `backend/services/correlation/engine.py`. The `3-attack-correlated.png` screenshot in Claude outputs shows that page. |
| g | Efficient SIEM and Data Lake integration | **Proven** | 15 output types tested against mock servers; Security Lake layout with `scripts/check_security_lake_layout.py`; per-output batching, retries, dead letters with automatic replay, delivery ledger. | — |
| h | AI/ML-ready security and operational analytics | **Not proven** | The schema is ML-friendly — typed, numeric ids, epoch times, Parquet, and every event records whether its parse was verified. | **Nothing in the project demonstrates it.** No feature export, no example, no baseline model. A judge asking "show me the ML-ready part" gets an explanation, not a run. |
| i | Reduced parser development effort | **Proven** | Generic parser: **85 correct, 18 missed, 0 wrong** on 13 formats with no pack; learned parsers **2,200/2,200** fields; learn → approve → re-parse tested end to end. | — |
| j | Deployable in an air-gapped network | **Partial — defect proven** | The pipeline makes no outbound calls; no LLM, no cloud dependency. | `.streamlit/config.toml` does not set `gatherUsageStats = false`, so the dashboard tries to phone home. FastAPI's default `/docs` loads Swagger UI from a CDN, so **the API docs page is blank offline**. No offline install bundle or instructions. |
| k | Packaged in a container | **Partial — defect proven** | `Dockerfile` and `docker-compose.yml` exist and are documented. | **No `.dockerignore`**: `COPY . .` bakes `.env`, `data/*.db`, `.git` and any local venv into the image — a secret leak. Runs as **root**. `build-essential` stays in the runtime image. The single-image `CMD` runs API and dashboard with `&`, so if the API dies the container still reports healthy. |

## The rest of the problem statement

| The PS says | Verdict | Proof found | What is lacking |
|---|---|---|---|
| Formats "such as Syslog, JSON, XML, CSV, CEF, LEEF, proprietary" | **Partial** | Syslog, JSON, CEF, LEEF, key=value and vendor formats probed today and read correctly. | **XML is not parsed at all.** A Windows Security event (4625) came back as a Base Event with nothing extracted; a device's XML with `<src>`/`<dst>` elements came back with no addresses. The PS names XML explicitly. CSV with a header row does not use the header. |
| "Scalable … Big Data environments handling billions of events per day" | **Partial** | Measured: 2,711 events/s single process on 2 vCPU; 1,978 on the i3 laptop; 4,866 with 2 shards. Benchmark in the repo. | No sharded **runtime** — only the benchmark shards. No measurement on real multi-core hardware. The natural scale-out (N instances in one Kafka consumer group, one chain each) depends on the Kafka offset fix. |
| "Preserving the original event data for forensic and compliance purposes" | **Partial** | Hash chain, tamper detection, audit report PDF, reconciliation. | No retention policy (CERT-In directions require 180 days) and no incident-export bundle. |
| Theme: **Blockchain & Cybersecurity** | **Partial** | Two append-only hash chains (events, delivery outcomes), verified end to end. | Anyone with database access can rebuild a chain consistently: nothing is signed and nothing is anchored outside. This is the theme's own question. |
| Perimeter devices "regardless of source, format, vendor" | **Partial** | Firewalls and IDS well covered. | Routers exporting **NetFlow/IPFIX** are not received at all. |
| (Implied by NTRO) the framework's own security | **Not proven** | — | No API authentication, CORS `*`, Streamlit XSRF protection switched off, open tamper endpoint, receivers accept any sender. |

## Deliverables

| Deliverable | State |
|---|---|
| Source code link | **Not pushed.** No git remote, no LICENSE file. |
| README with setup instructions | Quickstart and measured numbers added; the body is still the old 824-line file-by-file blueprint with 6 "ULPF" mentions. |
| Architecture document (max 2 pages) | **Missing.** |
| Demo video (max 2 minutes) | `tracelog-demo.mp4` is dated 21 Sep — **before eight commits**: the legacy archive, the measured dashboard, real OCSF export, the TRACELOG name, the throughput work, Security Lake, the OCSF decision and Snort. It shows a product that no longer exists. |
| Technical presentation (max 5 slides) | **Missing.** |

---

## What we lack, beyond the Kafka fix and the pfSense packs — ranked

**Tier 1 — fails a PS line a judge can check in two minutes (~7 h of code, plus the deliverables)**

1. **The deliverables** — push with a LICENSE, the 2-page architecture document, the README rewrite, re-record the video, the deck.
2. **Lossless, item (a)** (~2 h) — decode uploads with the same UTF-8/Latin-1 rule as streams instead of replacing bytes; stop stripping on the API; hash the bytes actually received. The hash is part of the chain, so this is a versioned change for non-UTF-8 lines, with the verifier taught both.
3. **XML** (~2 h) — flatten elements and attributes into key paths and run the same evidence rules; read Windows `EventData`'s `Name=` attributes; a Windows logon-failure pack mapping 4624/4625 to Authentication.
4. **The Correlation page's invented numbers** (~1 h, or 10 minutes to hide it) — the one place a judge can catch the product contradicting its own "every number is measured" claim.
5. **Air-gap, item (j)** (~1 h) — telemetry off, Swagger UI served locally, an offline-install section.
6. **Container, item (k)** (~45 min) — `.dockerignore`, a non-root user, a slim runtime stage, one process per container.

**Tier 2 — the theme, and proof for the claims (~9 h)**

7. **Signed chain checkpoints** (~2 h) — Ed25519 over sequence and chain head every N events, delivered to the outputs so the SIEM is an external witness. This is the Blockchain & Cybersecurity answer.
8. **AI/ML-ready, item (h)** (~2 h) — a script that loads the Parquet output, builds per-source time-window features and flags anomalies with a plain statistical baseline, plus a short doc; no new heavy dependency.
9. **Security baseline** (~3.5 h) — API token, CORS, Streamlit XSRF back on, tamper endpoint behind demo mode, receiver allow-list, line and upload limits.
10. **Router and WAF packs** (~2 h) — Cisco IOS (`%SEC-6-IPACCESSLOGP`, link and config events) and ModSecurity, the two perimeter devices that came back empty today.

**Tier 3 — completeness (~7 h)**

11. Retention setting (180 days) and an incident-export bundle (~1 h).
12. Sharded runtime and a benchmark on real multi-core hardware (~2 h plus an hour of a bigger machine).
13. NetFlow/IPFIX receiver (~2–3 h).
14. Adding outputs without a restart.

---

## How the probes were run

The lossless, traceability, format and device checks came from a throwaway script against a
temporary database, feeding crafted bytes through the stream, single-line API and upload paths and
reading back what was stored. The ML, air-gap, container, security and scale checks are searches of
the code for what would have to exist, with the file named where something was found. Numbers
quoted as measured come from `scripts/benchmark.py`, `scripts/evaluate_unseen_formats.py` and the
third-party corpus run.
