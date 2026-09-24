# TRACELOG — where we stand, and what is left

SIH 2026 · PS 26156 (NTRO) · status as of 24 September 2026
Repository state: local `main` at `8ee53e3`, 147 tests passing, not yet on GitHub.

Maturity is rated as:

- **Shipped** — built, tested, and safe to demo.
- **Thin** — works, but a judge who pushes on it finds the edge.
- **Demo-only** — looks finished on screen, is not finished underneath.
- **Missing** — not built.

---

## 1. Ingestion and connectors

| Feature | Maturity | Where it stands |
|---|---|---|
| Syslog UDP + TCP receivers (5514) | Shipped | Auto-registers the sending device as a source on first sight. No TLS, no sender allow-list, newline framing only (not RFC 6587 octet counting). |
| Splunk HEC, OTLP, `/api/ingest/stream` | Shipped | Token check exists in config but the token list ships empty, so the receivers accept from anyone. |
| File tail input | Shipped | Used by the live Suricata sensor compose file. |
| Kafka input | Thin | Implemented and unit-tested against a mock; offsets are committed before the event is stored, so a crash loses the batch. |
| File upload + single-line API | Shipped | Upload has no size limit — a compressed bomb ends the process. |
| NetFlow / IPFIX | Missing | Named in the PS's device list by implication (perimeter routers). |
| IPv6, per-source timezone | Thin | Handled unevenly across packs. |

## 2. Parsing — the core differentiator

| Feature | Maturity | Where it stands |
|---|---|---|
| Vendor packs (11) | Shipped | Cisco ASA/FTD, PAN-OS, FortiGate, Check Point, Juniper SRX, Sophos, SonicWall, pfSense, Suricata, Snort, Zeek. |
| CEF / LEEF standard formats | Shipped | Recognised as standards, marked verified, not as "new formats". |
| Evidence-based generic parser | Shipped | **85 correct, 18 missed, 0 wrong** over 103 fields in 13 formats with no pack. The zero is the claim everything else rests on. |
| Third-party validation | Shipped, unpublished | Against 2,356 real vendor sample lines (Elastic integrations fixtures): **90.9 % read by a vendor pack, 0 crashes, 0 OCSF-invalid**. Weak spots: pfSense 33 %, Snort 20 %. Not in the repo — those files are Elastic-licensed. |
| XML / Windows Event XML | Missing | Lines go to the generic parser and mostly come back empty. |

## 3. Learning new formats

| Feature | Maturity | Where it stands |
|---|---|---|
| Format fingerprint + registry | Shipped | Near-identical templates merge; new formats surface in Parser Studio. |
| Parser learning with held-out validation | Shipped | 70/30 split, per-field roles with reasons, `needs_review` gate a person must clear. |
| Approval, hot reload, re-parse history | Shipped | Verified live: 920 events, 150 revisions, chain valid, reconciliation 920/920. Originals are never rewritten — the correction is appended and linked. |
| Legacy "Generate & Test" tab | Demo-only | Still in Parser Studio from the old app. Hide it or delete it before the video. |

## 4. Normalisation

| Feature | Maturity | Where it stands |
|---|---|---|
| OCSF 1.1.0, 4 classes | Shipped | Network Activity 4001, Authentication 3002, Detection Finding 2004, Base Event 0. |
| Strict export + validator | Shipped | `to_ocsf()` + `validate()`, epoch-ms time, measured conformance on the dashboard. |
| DNS (4003), HTTP (4002), File, Process | Missing | Proxies and DNS servers are perimeter sources; these are the obvious next two. |
| OCSF version story | Thin | We target 1.1.0 while 1.9.0 exists. Defensible (Security Lake accepts ≤1.3) but must be said out loud, not discovered. |

## 5. Integrity and chain of custody

| Feature | Maturity | Where it stands |
|---|---|---|
| Per-line SHA-256 + hash chain | Shipped | `H(prev : seq : raw_hash : canonical_json)`, verified end to end. |
| Tamper demo and restore | Demo-only (by design) | Works, but the endpoint is open to anyone — it must be behind a demo flag. |
| Audit report (PDF) | Shipped | Downloadable. |
| Reconciliation + delivery ledger | Shipped | Proves what each output received. |
| Dead letters + automatic replay | Shipped | Verified by killing a sink mid-stream and watching it drain. |
| Keyed / externally anchored chain | Missing | Someone with database access can rebuild the whole chain. This is the question a serious judge asks. |

## 6. Delivery to SIEMs

| Feature | Maturity | Where it stands |
|---|---|---|
| 15 sink types | Shipped | Splunk HEC, Elasticsearch, OpenSearch, Wazuh, Loki, OTLP, Sentinel, webhook, Datadog, New Relic, syslog, GELF, Kafka, file, Parquet. |
| Retries, filters, queueing, ledger | Shipped | Per-output batch size, backoff, dead letters. |
| Parquet / data lake | Thin | Writes `class_uid=*/event_day=*`. Amazon Security Lake wants `region/accountId/eventDay` and one class per object — close, not claimable yet. |

## 7. Dashboard

| Page | Maturity | Where it stands |
|---|---|---|
| Overview, Pipeline, Explorer, Schema | Shipped | Every number measured from the database; new-format banner; OCSF validate badge. |
| Parser Studio + New formats | Shipped | The learn → confirm → approve → re-parse flow. |
| Integrity, Integrations, Sources | Shipped | |
| **Correlation & RCA** | **Demo-only — liability** | Confidence scores are hardcoded constants (0.88, 0.92, 0.85, 0.89, 0.75). One click here undoes the "every number is measured" story. |
| Settings | Thin | |

## 8. Performance

| Feature | Maturity | Where it stands |
|---|---|---|
| Benchmark harness | Shipped | `scripts/benchmark.py`, with `-w N` for N shards, each with its own chain. |
| Measured rates | Shipped | 2,711 events/s single process at 20k events; 1,622 at 100k; 4,866 aggregate with 2 shards — all on 2 cores. Reads are milliseconds. |
| Sharded **runtime** | Missing | Only the benchmark shards. The product itself is one process. |
| Numbers on real hardware | Missing | Everything so far is a 2-core box. A competitor is claiming 13,000/s. |

## 9. Security — nothing applied yet

No API authentication. CORS `*`. Open syslog and HTTP receivers. Open tamper endpoint. Unkeyed chain. A 16 KB pathological line takes 2.6 s to parse. No upload size limit. Container runs as root, no `.dockerignore`. Streamlit telemetry on, Swagger from a CDN (both break the air-gap claim). Unused LLM API-key fields in config.

## 10. Deliverables

| Deliverable | State |
|---|---|
| Source link (GitHub) | **Not pushed.** No remote configured, no LICENSE file. |
| README | Half done — quickstart and measured numbers added, but the body is still the old file-by-file blueprint and six "ULPF" references remain. |
| Architecture document (max 2 pages) | **Missing.** |
| Demo video (max 2 min) | **Missing.** |
| Technical presentation (max 5 slides) | **Missing.** |

---

## What actually makes us stand out

Ranked by how hard it is for another team to match:

1. **Zero wrong fields on unknown formats.** Everyone else claims "AI-powered parsing". Nobody else reports a wrong-field count, because theirs is not zero. This is the whole product in one number and it is currently invisible in the README's first screen and absent from the video.
2. **Corrections that never rewrite history.** Learn a parser, approve it, re-parse the past — and the original event stays in the chain with the revision linked to it. This is what "chain of custody" means, and it is genuinely rare.
3. **Proof of delivery, not just delivery.** Delivery ledger, reconciliation, dead-letter replay. Demonstrated by breaking the sink on camera, which nobody does.
4. **Measured numbers everywhere.** A dashboard that says 33.3 % when three events arrived. Unusual enough that it should be said out loud.
5. **Breadth of real connectors.** 15 output types is more than most teams will have looked at.

What does **not** differentiate us: another hash-chain claim (everyone says it), OCSF (the PS asks for it), a pretty dashboard.

---

## Execution plan

Estimates assume one person per item unless noted. Acceptance criteria are written so that "done" is not a matter of opinion.

### P0 — submission-blocking (do these first, ~9 hours total)

**P0.1 Push to GitHub (45 min).**
Add a LICENSE, confirm `.env` was never committed and no token literal is in history, push `main` and `archive/legacy-app`, tag `v1.0`.
*Done when:* a fresh `git clone` on another machine passes `pytest -q` with 147 passed by following `docs/RUNBOOK.md` alone.

**P0.2 Neutralise the fake numbers in Correlation & RCA (1 h).**
Either hide the page for the submission, or replace each hardcoded confidence with the counted evidence behind it (how many events, over what window, matched by what rule). Hiding is acceptable; leaving invented numbers on screen is not.
*Done when:* no constant confidence value exists in `backend/services/correlation/engine.py`, or the page is not reachable from the navigation.

**P0.3 README first screen (1 h).**
One sentence on what it does, the 5-minute quickstart, the three measured numbers (0 wrong fields, events/s with hardware, OCSF conformance), and a judge tour: "click these five things in this order". Move the file-by-file blueprint to the bottom or into `docs/`. Remove the remaining ULPF references.
*Done when:* someone who has never seen the repo can run it and reach the Overview page inside five minutes, using only what is above the fold.

**P0.4 Architecture document, 2 pages (2 h).**
Page 1: the flow diagram and the four-tier parser. Page 2: design decisions with reasons — why OCSF 1.1.0, why append-only revisions, what the hash chain does and does not prove, the security posture stated honestly, measured performance, and the roadmap.
*Done when:* it is exactly two pages and every claim in it maps to something runnable in the repo.

**P0.5 Demo video, 2 minutes (2 h with retakes).**
Beats: problem (10 s) → unknown format parsed with no wrong fields (20 s) → learn, approve, re-parse with the original preserved (25 s) → tamper, detect, restore (20 s) → sink down, dead letters drain (20 s) → measured dashboard and throughput (15 s) → close (10 s). Record on a frozen build, after P0.2.
*Done when:* under 2 minutes, no slides inside it, and nothing on screen is a number we cannot reproduce.

**P0.6 Five slides (1.5 h).**
Problem and solution; architecture; the differentiator with the corpus numbers; integrity and delivery guarantees; measured performance and the profiled roadmap.

**P0.7 Freeze and verify (45 min).**
Full test suite, fresh-clone install check, the unseen-format score, a chain verification on the demo database.

### P1 — credibility, before anyone asks (~6 hours)

**P1.1 Security baseline (3.5 h).**
API token from the environment on every route (empty token = open, so the quickstart still works); CORS restricted to the UI origin; tamper endpoint behind `DEMO_MODE`; receiver IP allow-list; max line length plus a per-line parse time budget; upload size cap; non-root container and `.dockerignore`. Plus `tests/test_security.py` with one test per item.
*Done when:* those tests pass and the README has a short "security posture: protected / assumed / out of scope" section.

**P1.2 Public-sample scorecard (45 min).**
`scripts/evaluate_public_samples.py` fetches third-party vendor sample logs on demand and prints the per-vendor table. Nothing licensed gets committed.
*Done when:* the README carries the 90.9 % figure with the command that reproduces it.

**P1.3 Benchmark on real hardware (1 h, needs a better machine or an hour of EC2).**
Run the three benchmark commands on 8 cores, record CPU model, cores, RAM, single-process and sharded rates.
*Done when:* `docs/PERFORMANCE.md` carries a second table headed by the hardware, and the deck quotes it.

**P1.4 Air-gap truth (45 min).**
Streamlit telemetry off, Swagger assets served locally, a short "install with no internet" section.
*Done when:* the UI and `/docs` both work with the network cable out.

### P2 — the things that win the room (~8 hours)

**P2.1 Signed checkpoints to the SIEM (2 h).**
Every N events or T seconds, emit an Ed25519-signed checkpoint (sequence, chain head, count) through the output connectors, so the SIEM becomes an external witness. Turns "what if the admin is the attacker?" from a weakness into the memorable slide.
*Done when:* a checkpoint arrives at a sink, verifies against the public key, and a test shows that rewriting the database makes a delivered checkpoint fail.

**P2.2 Sharded runtime (2 h).**
N ingest workers partitioned by source, one chain per shard, a documented shard map, and the scaling curve at 1/2/4 workers in the docs.
*Done when:* the product — not just the benchmark — uses N workers, and each shard's chain verifies independently.

**P2.3 pfSense and Snort pack coverage (1.5 h).**
The two weak spots on third-party data (33 % and 20 %). Add the missing sub-formats.
*Done when:* both are above 80 % on the public-sample scorecard.

**P2.4 OCSF DNS (4003) and HTTP (4002) (1.5 h).**
*Done when:* proxy and DNS lines land in the right class and pass `validate()`.

**P2.5 CERT-In alignment (1 h).**
A retention setting defaulting to 180 days, an incident export bundling events, raw lines and chain proofs for a time window, and NTP guidance in the docs.
*Done when:* the architecture document names the CERT-In directions and the settings that implement them.

### P3 — after the deadline

XML and Windows Event support; NetFlow/IPFIX receiver; Security Lake partition layout for the Parquet sink; columnar parsing with Polars (profiled, designed, deliberately not rushed); offline wheel/image bundle; Kafka offset-after-store fix; TCP octet framing; disk-full handling.

---

## Suggested order if time is short

If only one day remains: P0 entirely, then P1.1 and P1.2. Nothing else.
If two days: add P1.3, P1.4, P2.1 and P2.3.
If three: the whole of P2.

The freeze rule holds regardless — no code merges after the video is recorded, and the last hour stays empty as a buffer.
