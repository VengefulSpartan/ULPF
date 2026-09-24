# TRACELOG: rejection risks, PS gap analysis and the Rust question

SIH 2026 · PS 26156 (NTRO) · Universal Log Pre-processing Framework
Covers the conversation from "we are currently behind all the other teams that have given a solution on GitHub…" up to the request to export it.

> **Note on this file.** The chat history was compacted before this export was requested, so the original replies could not be copied word for word. What follows is rebuilt from the session's working notes. It keeps every point, number and source from those replies, and a "Status" line is added where something has been fixed since. The earlier export (`tracelog-workflow-ppt-guide.md`) was copied verbatim.

## Contents

1. [Everything that could get us rejected](#1-everything-that-could-get-us-rejected)
2. [PS requirements: where we fall short, the options, and the pick for each](#2-ps-requirements-where-we-fall-short-the-options-and-the-pick-for-each)
3. [Should we rewrite the engine in Rust?](#3-should-we-rewrite-the-engine-in-rust)
4. [Status as of 22 Sep 2026](#4-status-as-of-22-sep-2026)

---

## 1. Everything that could get us rejected

**Request:** "we are currently behind all the other teams that have given a solution on GitHub...list out all the possible points that will get us rejected"

Judges usually spend a few minutes per repo. They open the README, glance at the tree, maybe run it, and then watch the video. Most rejections happen in that pass, so the risks below are ordered by how soon a judge would see them.

### A. First impression of the repository

| # | Risk | Why it hurts | Status |
|---|---|---|---|
| A1 | Two parallel apps in one repo (the legacy `api/ core/ ingest/ rca/ storage/ ui/` app next to `backend/ frontend/`) | It looks unfinished and makes the judge ask which one is the product | **Fixed**: legacy app archived (branch `archive/legacy-app`) |
| A2 | Three names in use (ULPF, TRACELOG and the old app name) | It reads as copy-paste or a team that isn't aligned | **Fixed**: TRACELOG everywhere |
| A3 | The README is long, contains a personal Windows path, and has no 5-minute quickstart | Judges who can't run it in 5 minutes stop trying | Pending (README rewrite) |
| A4 | No 2-page architecture document, which is a named deliverable | A missing deliverable counts against the whole submission | Pending (`docs/ARCHITECTURE.md`) |
| A5 | Unused dependencies in requirements (drain3, networkx, minio, opensearch-py…) | It suggests claimed features that aren't there | **Fixed** |
| A6 | Packaging named the wrong modules (`ulpf`) | `pip install .` did not produce the product | **Fixed**: `pyproject.toml` packages `backend`/`frontend` |

### B. Honesty of the numbers

| # | Risk | Status |
|---|---|---|
| B1 | Hard-coded dashboard numbers (for example "99.4 %" parser success) | **Fixed**: every card is measured from the database |
| B2 | Pipeline page showed fixed stage counts | **Fixed**: measured stages, parser table, unparsed lines |
| B3 | The traffic generator was presented as "real device traffic" | **Fixed**: renamed to `send_sample_attack.py` and described as samples |
| B4 | No published benchmark (events/s, latency, hardware) | Open; measured ~1,700–2,000 ev/s on known formats and ~900–1,200 on unknown, single process, but not yet written up |
| B5 | No accuracy figure for unseen formats | Measured: 85 correct / 18 missed / **0 wrong** on the unseen corpus; learned parsers 2,200/2,200. This needs to go in the README |

### C. Correctness of the OCSF output

| # | Risk | Status |
|---|---|---|
| C1 | The "OCSF export" wasn't strict OCSF (internal field names, ISO time) | **Fixed**: `to_ocsf()` plus `validate()`, epoch-ms time |
| C2 | Yearless syslog timestamps landed in 1900 | **Fixed**: current year, rolled back when more than 2 days in the future |
| C3 | CEF/LEEF treated as "new unknown formats" | **Fixed**: `generic_cef` / `generic_leef` standard packs, verified |
| C4 | Directionless traffic classified as Base Event | **Fixed**: becomes Network Activity (4001) with endpoints left empty |
| C5 | Only 4 OCSF classes (4001, 3002, 2004, 0) | Open; DNS (4003), HTTP (4002), File (1001) and Process (1007) are the obvious next ones |
| C6 | Pinned to OCSF 1.1.0 while the current release is 1.9.0 | Open; this should be a deliberate choice, since Security Lake accepts ≤1.3, so say that |

### D. Security (a judge from NTRO will look)

| # | Risk | Status |
|---|---|---|
| D1 | No authentication on the API or the UI | Open |
| D2 | CORS `*` | Open |
| D3 | The demo "tamper" endpoint is open to anyone | Open; gate it behind a demo flag |
| D4 | Syslog/HTTP receivers accept from anyone (no allow-list, no TLS) | Open |
| D5 | The hash chain is unkeyed: someone with DB access can rebuild the whole chain | Open; fix with HMAC or signed checkpoints anchored outside (see §2) |
| D6 | The restore path has a bug | Open |
| D7 | A 16 KB pathological line takes ~2.6 s to parse (a regex DoS) | Open; needs a line cap and time budget |
| D8 | Gzip upload has no size limit (a gzip bomb) | Open |
| D9 | The container runs as root and there's no `.dockerignore` | Open |
| D10 | An LLM API-key path exists in config | Open; removal not yet approved |

### E. Air-gap claim

| # | Risk | Status |
|---|---|---|
| E1 | Streamlit sends usage telemetry by default | Open; `gatherUsageStats=false` |
| E2 | Swagger UI loads from a CDN | Open; serve the assets locally |
| E3 | No offline bundle (wheels and images) and no install-without-internet doc | Open |
| E4 | NTP is not addressed; timestamps are only as good as the host clock | Open; document NIC/NPL NTP |

### F. Reliability under load

| # | Risk | Status |
|---|---|---|
| F1 | A full disk kills the worker silently | Open |
| F2 | Kafka offsets committed before the event is stored | Open |
| F3 | TCP syslog framing: only newline, no octet-counting (RFC 6587) | Open |
| F4 | IPv6 addresses are handled unevenly by some packs | Open |
| F5 | Timezone of the source device is assumed, not configured per source | Open |
| F6 | SQLite with a single writer; no horizontal scale story | Open; a sharding design is needed (see §3) |

### G. Coverage gaps against the PS

| # | Risk | Status |
|---|---|---|
| G1 | XML logs (e.g. Windows EVTX exported as XML) go unparsed | Open |
| G2 | No NetFlow/IPFIX input | Open |
| G3 | No CERT-In 180-day retention setting or incident-reporting (6-hour) export | Open |
| G4 | The Security Lake / Parquet output isn't implemented | Open |

### H. Leftovers and UI rough edges

| # | Risk | Status |
|---|---|---|
| H1 | The old "Generate & Test" tab is still in Parser Studio | Open |
| H2 | RCA page uses constants | Open |
| H3 | The frontend has a duplicated fallback path for the API client | Open |
| H4 | 25 leftover test YAML parsers in `core/plugins` (ignored files, still on disk) | Ask before deleting |
| H5 | The demo video and the 5-slide deck are not yet recorded or made | Open |

### Fix order that was proposed

1. Repo hygiene and honesty: A1–A6 and B1–B3 (**done**).
2. Correct OCSF: C1–C4 (**done**).
3. README quickstart, judge tour, 2-page architecture document, and the published benchmark with the accuracy numbers (A3, A4, B4, B5).
4. The cheapest security fixes that a judge can check: auth token, CORS, tamper flag, line cap, gzip limit, non-root container (D1–D3, D7–D9).
5. Air-gap truth: telemetry off, local Swagger, offline bundle doc (E1–E3).
6. Keyed integrity with signed checkpoints (D5).
7. Coverage: XML, more OCSF classes, NetFlow (C5, G1, G2).
8. Video and deck last, recorded on the fixed build.

---

## 2. PS requirements: where we fall short, the options, and the pick for each

**Request:** "first markout all the requirements of the problem statement and how our project fails it research for multiple possible methods to solve them and get the solution with the most amount of impact on the judges"

### 2.1 Requirements vs. current state

| PS asks for | What TRACELOG does today | Gap |
|---|---|---|
| Ingest logs from heterogeneous perimeter devices (firewalls, IDS/IPS, routers, VPN, proxies) | Syslog UDP/TCP, HTTP, file upload, Kafka; vendor packs for Cisco ASA, Palo Alto, Fortinet, pfSense, Suricata/Snort, CEF/LEEF, etc. | No NetFlow/IPFIX, no XML, no TLS syslog |
| Handle unknown / new formats | Evidence-based generic parser (no wrong fields: 0 wrong on the unseen corpus); a format registry; a learner with a 70/30 held-out check; human approval; re-parse history as chained revisions | Accuracy is not shown to judges yet |
| Normalize to a common schema | OCSF 1.1.0, strict export and validation, 4 classes | Few classes; old OCSF version |
| Lossless storage of the raw line | Raw archived with SHA-256 per line | Stored as text, not exact bytes (encoding edge cases) |
| Integrity / tamper evidence | SHA-256 hash chain, verification, reconciliation 920/920, audit report | Unkeyed; no external anchor |
| Forward to SIEMs | Output connectors (syslog/CEF, HTTP/JSON, file, Kafka) with a delivery ledger and dead-letter replay | No Parquet/Security Lake; no Splunk HEC or Elastic bulk-specific connector |
| Air-gapped / on-prem deployment | Docker Compose, no cloud calls in the pipeline | Telemetry, CDN, no offline install bundle |
| Scale / performance | ~1,700–2,000 ev/s known formats and ~900–1,200 unknown, one process | No published benchmark, no multi-core design |
| Security of the framework itself | — | No auth, open receivers, CORS * |
| Compliance context (Indian) | — | CERT-In retention, incident reporting, NTP not addressed |
| Deliverables: source, README, ≤2-page architecture document, ≤2-min video, ≤5 slides | Source ready | README short version, architecture document, video and slides still to do |

### 2.2 Options per gap, and the pick

**Integrity that survives someone with database access (D5)**
- Option 1: HMAC the chain with a key held outside the database. It's cheap, but a stolen key forges everything.
- Option 2: signed syslog per RFC 5848. It's a standard, but it's per-message and heavy, and few SIEMs verify it.
- Option 3: Merkle transparency log (RFC 6962 / Trillian). This is the gold standard but too big for the timeline.
- **Pick:** keep the SHA-256 chain, and every N events or T seconds emit an **Ed25519-signed checkpoint** (sequence, chain head, count) *to the SIEM itself*. The SIEM becomes an external witness: rewriting our database can't change checkpoints already delivered elsewhere. This is the transparency-log idea (research.swtch.com/tlog) in about 150 lines. It's high judge impact because it answers "what if the admin is the attacker?".

**Unknown formats: making the strength visible (B5)**
- **Pick:** publish the unseen-corpus result (85 correct, 18 missed, 0 wrong) and the learned-parser result (2,200/2,200) in the README and on a dashboard card, and show "learn → approve → re-parse" live in the video. Other teams mostly claim "AI parsing"; we can show zero wrong fields and an audit trail of revisions.

**Schema version and classes (C5, C6)**
- Options: jump to OCSF 1.9.0; stay on 1.1.0; support both.
- **Pick:** stay on 1.1.0 for export (AWS Security Lake custom sources accept OCSF ≤1.3), state that reason in the architecture document, and add DNS Activity (4003) and HTTP Activity (4002) next, because proxies and DNS servers are perimeter sources named in the PS.

**SIEM delivery breadth (G4)**
- **Pick:** add a Parquet writer laid out as Security Lake expects: one OCSF class per object, partitions `region/accountId/eventDay`, zstd compression. This shows "SIEM-agnostic" is real. Splunk HEC and Elastic `_bulk` are small additions on top of the HTTP connector.

**NetFlow (G2)**
- Options: write a v5/v9/IPFIX decoder; use the `netflow` package on PyPI; accept flows via a collector such as nfcapd and read its output.
- **Pick:** the PyPI `netflow` package for v5/v9/IPFIX on a UDP receiver, mapped to OCSF Network Activity. Keep it small and label it clearly.

**XML (G1)**
- **Pick:** add an XML path in the generic parser (flatten elements/attributes to key paths, then the same evidence rules), plus a Windows Event XML pack for the common auth event IDs to Authentication (3002).

**Air-gap (E1–E3)**
- **Pick:** Streamlit telemetry off in config, serve Swagger assets locally, and an `offline/` script that builds a wheelhouse and `docker save` images, with a one-page "install with no internet" section. It's cheap, and a judge can verify it.

**Security baseline (D1–D4, D7–D9)**
- **Pick:**
  - API token (environment variable, never committed) on every API route plus the UI;
  - CORS limited to the UI origin;
  - the tamper endpoint only when `TRACELOG_DEMO=1`;
  - receiver IP allow-list;
  - a maximum line length and a per-line parse time budget;
  - a limit on decompressed upload size;
  - a non-root container user and a `.dockerignore`.

**Indian compliance (G3, E4)**
- **Pick:**
  - a retention setting defaulting to **180 days** (CERT-In directions, April 2022);
  - an "incident export" that bundles events, raw lines and chain proofs for a time window, to support the **6-hour** reporting window;
  - documentation of NTP sync to NIC/NPL servers, as the CERT-In directions require.

  This is a strong NTRO-specific signal that few teams will have.

**Performance (B4, F6)**
- **Pick:** a reproducible benchmark script and a table (hardware, events/s, p50/p99 latency) for known and unknown formats, plus a sharded design in the architecture document: N parser workers by source and a single chain writer. See §3 on why this, not Rust.

### 2.3 Ranked plan (most judge impact per hour first)

1. README quickstart and judge tour, plus the measured accuracy and benchmark numbers.
2. 2-page architecture document with the flow diagram and the design reasons (OCSF version, chain, re-parse revisions).
3. Security baseline (token, CORS, tamper flag, limits, non-root).
4. Signed checkpoints delivered to the SIEM (external witness).
5. Air-gap fixes and the offline bundle.
6. CERT-In retention, incident export and the NTP note.
7. OCSF DNS and HTTP classes.
8. XML path plus the Windows Event pack.
9. Parquet / Security Lake output.
10. NetFlow receiver.
11. The 2-minute video and 5-slide deck, recorded on the finished build.

### 2.4 Sources used

- OCSF schema releases (1.1.0 through 1.9.0, Aug 2026): github.com/ocsf/ocsf-schema/releases
- AWS Security Lake custom sources (OCSF ≤1.3, Parquet, one class per object, partitioning, zstd): docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
- CERT-In Directions under section 70B(6) of the IT Act, 28 April 2022 (180-day log retention, 6-hour reporting, NTP sync): cert-in.org.in (Directions PDF and FAQs)
- RFC 5848, Signed Syslog Messages
- RFC 6962, Certificate Transparency (Merkle audit and consistency proofs)
- Trillian: github.com/google/trillian
- Russ Cox, "Transparent Logs for Skeptical Clients": research.swtch.com/tlog
- RFC 6587, Transmission of Syslog Messages over TCP (octet counting)
- `netflow` package on PyPI (NetFlow v1/v5/v9 and IPFIX in Python)

---

## 3. Should we rewrite the engine in Rust?

**Request:** "should we convert our entire python based engine into rust based for better throughput...evaluate on the basis of urgency and necessity"

### Short answer

**No, not before submission.** It is neither urgent nor necessary. The judges score whether the PS is solved and whether the claims are believable. A rewrite would take weeks, bring back bugs we have already fixed, and leave no time for the gaps in §1–§2, which are what would actually get us rejected.

### What profiling showed (single process)

| Workload | Throughput | Where CPU goes |
|---|---|---|
| Known formats (vendor packs) | ~1,700–2,000 events/s | Normalization (Pydantic model building and validation) **≈42 %**, parsing next, then hashing and the SQLite write |
| Unknown formats (generic parser) | ~900–1,200 events/s | Parsing / inference **≈54 %** |

So the bottleneck is not "Python is slow" in general. It is two specific hot spots that can be fixed in Python.

### Urgency

- Nothing in the PS sets a throughput number that we fail.
- Deliverables due before the deadline (README, architecture document, video, deck) are all missing, and so are the security basics. Those are urgent.
- **Urgency: low.**

### Necessity

- A mid-size perimeter (a few firewalls, IDS, VPN) generates hundreds to low thousands of events/s. One process already covers that, and several processes cover a lot more.
- For NTRO-scale traffic, what matters is horizontal scale (more workers), not the speed of one core.
- **Necessity: low now; revisit only if a benchmark on real hardware shows a need that sharding can't meet.**

### Risk of rewriting

- We would have to re-verify everything that has been verified: 137 tests, the unseen corpus results (0 wrong), chain validity, reconciliation 920/920, and the learn/approve/re-parse flow.
- The team would split between two codebases during the most important weeks.
- Judges can't see the language; they can see a broken demo.

### What to do instead

1. **Python hot-spot fixes (days, not weeks).**
   - Build the Pydantic model once per event with `model_construct` on already-validated data, or validate in a single pass.
   - Precompile and cache the regexes and fingerprints per format.
   - Batch SQLite writes in one transaction per batch.
   - Use `orjson` for serialization.
2. **Multi-core by sharding.**
   - N parser/normalizer worker processes, partitioned by source.
   - One chain writer that assigns sequence numbers and hashes in order, because the chain has to be sequential anyway.
   - This scales roughly with cores while keeping the integrity model.
3. **Publish a benchmark:** a script, the hardware, events/s, and p50/p99 latency, before and after. A measured number beats a language claim.
4. **Leave Rust as the roadmap slide.** An optional native module (PyO3) for the tokenizer/fingerprint step is a sensible future step. Say "profiled, targeted, optional", not "rewritten".

---

## 4. Status as of 22 Sep 2026

- Applied to the local project folder (`SIH26`, branch `main`):
  - **9939b7b** Archive the legacy parallel app; package only the product.
  - **adbbebf** Show measured numbers only, export real OCSF, fix dates; one name: TRACELOG.
- The previous state is kept on branch `archive/legacy-app`.
- Test suite: 137 passed. The earlier count of 242 included 111 tests of the archived legacy app.
- Next: README rewrite and `docs/ARCHITECTURE.md`, then items 3–11 of the ranked plan once approved.
