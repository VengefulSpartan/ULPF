# TRACELOG against PS 26156 — status, requirement by requirement

Checked on 25 September 2026 against `main` at `bda4551` (302 tests passing). Every verdict rests on
something run for this check: a probe against a throwaway database, a test, a measured number, or
the real-log run. Nothing here is carried over from an earlier audit without being re-run.

Verdicts: **Met** (evidence a judge can rerun), **Partial** (works, with a named hole), **Not met**
(nothing in the project does it yet).

## The short answer

Not all of it. Of the eleven expected outcomes, ten are met with proof and the container is met in
its build files but has not been built once end to end. AI/ML-ready (h), the one that was not met,
is now met on synthetic data; what it still lacks is a run on a real network's logs. Outside the
eleven, **the framework's own security is not met**, and scale, the blockchain theme, compliance
retention and device coverage are partial. Three deliverables are **missing or out of date**: the
five-slide deck, the demo video and a LICENSE, and the architecture document still needs a two-page
PDF.

## Expected solutions (a)–(k)

| # | The PS asks | Verdict | Proof, as run for this check | What is still missing |
|---|---|---|---|---|
| a | Preserve complete raw event data | **Met** | Stream: CRLF, Latin-1, invalid UTF-8 and padded lines all reproducible byte for byte and proven by the stored SHA-256 (4/4). API keeps whitespace. Upload keeps `café`. A line whose parser crashes is still archived and chained (`tests/test_lossless.py`). | — |
| b | Extract source-specific attributes | **Met**, coverage gaps | 12 vendor packs plus CEF/LEEF; the device's own field names kept. Real logs: 3,156 of 7,768 perimeter lines read by a pack, 0 crashes. | Weak on real logs: Cisco FTD 430002/430003, WatchGuard, Cisco IOS, ModSecurity, Squid (probe: IOS ACL, ModSecurity, Squid give no addresses). |
| c | Normalise into a common taxonomy | **Met** | OCSF 1.1.0; 0 invalid events on 17,768 real lines; version decision in ADR 0001. | Four classes only; HTTP/DNS/DHCP activity lands as Base or Network events. |
| d | Traceability normalised ↔ original | **Met** | 5/5 exported events resolve to their raw line, hash matches, chain record present. | Chain not signed or anchored outside the database (see theme). |
| e | Plug-and-play onboarding | **Met** | Devices register themselves by hostname; unknown formats detected, learned, approved and live within 5 s without a restart. | Parser Studio's "Generate & Test" tab stores parsers the pipeline never applies — hide or relabel it before a demo. |
| f | Unified visibility | **Met** | One OCSF shape for every source; every dashboard number read from the database; correlation shows evidence, no invented scores (no constants found in `correlation/`). | Three correlation rules only. |
| g | SIEM and data lake integration | **Met** | 15 output types tested against mock servers; dead letters with automatic replay; delivery ledger and reconciliation; Security Lake layout. | Kafka input commits offsets when records reach memory, before they are stored. |
| h | AI/ML-ready analytics | **Met**, on synthetic data | A typed Parquet row per event: null where the device did not say, which parser read it, verified or inferred, raw-line hash. Per-entity 5-minute features that never see a later window (tested). A baseline detector whose flags become OCSF Detection Findings in the hash chain. Synthetic days, 3 seeds: 6 of 6 detectable attacks caught every time, the 2 built to be missed missed, 1 benign false flag a day; every finding valid OCSF, 876/876 evidence events resolve to their archived lines, a rerun writes nothing (`docs/ML_DATA.md`, `docs/ML_EVALUATION.md`). | Never run on real traffic, so its real false-flag rate is unknown. Per-window with 24 h of memory: slow attacks and daily jobs are outside it. No dashboard page for its flags (they show in the Explorer and the SIEMs as Detection Findings). |
| i | Reduced parser development effort | **Met** | Formats with no parser: 85 correct, 18 missed, **0 wrong**; learned parsers 2,200/2,200 fields on new lines. | — |
| j | Air-gapped deployment | **Met** | `/docs` references no external URL; usage statistics off; with the network cut off, 0 requests leave the machine and all 54 API endpoints render (`docs/AIRGAP.md`). | — |
| k | Containerised | **Met in the build files** | `.dockerignore` keeps secrets, data and history out (checked on the build context); non-root, no compiler, one process per container, health check, read-only compose (`tests/test_container.py`). | The image has not been built end to end once: run `sh scripts/check_image.sh` on a machine with Docker. |

## The rest of the problem statement

| The PS says | Verdict | Proof | What is still missing |
|---|---|---|---|
| Formats: Syslog, JSON, XML, CSV, CEF, LEEF, proprietary | **Met** | Probe: Windows XML → Authentication with user and address; generic XML, CEF, LEEF, JSON → both addresses; uploaded CSV with a header → rows read by column name; proprietary formats via packs or learning. | — |
| Billions of events per day | **Partial** | Measured today on 2 vCPUs: 1,818–2,427 events/s per process across runs on shared hardware (157–210 M/day), 4,739 with two shards (409 M/day). The ML change did not move it: 1,837 before, 1,818 after, back to back. | 1 billion/day is 11,574 events/s: needs about five shards on multi-core hardware, never measured, and a sharded runtime that does not exist yet (only the benchmark shards). |
| Preserving data for forensic and compliance purposes | **Partial** | Byte-exact archive, two hash chains, tamper detection, audit report PDF/JSON with fingerprint. | No retention setting (CERT-In: 180 days); no incident-export bundle. |
| Theme: Blockchain & Cybersecurity | **Partial** | Append-only SHA-256 chains for events and deliveries, verified end to end. | Nothing signed or anchored outside the database: whoever controls it can rebuild a consistent chain. Signed checkpoints sent to the SIEMs would close this. |
| Perimeter devices "regardless of source, format, vendor" | **Partial** | Firewalls and IDS/IPS well covered; everything is accepted and archived. | Router, WAF and proxy logs mostly unparsed; NetFlow/IPFIX not received. |
| (Implied for NTRO) the framework's own security | **Not met** | Probe: `GET /api/events` → 200 with no credentials; CORS reflects any origin; Streamlit XSRF off; tamper endpoint reachable. | API token, CORS allow-list, XSRF on, tamper endpoint behind a demo switch, syslog sender allow-list (which also stops anyone imitating the detector's findings over syslog; today their transport gives them away). |

## Deliverables

| Deliverable | State |
|---|---|
| Source code link | On GitHub (`VengefulSpartan/ULPF`), two commits behind local `main`. **No LICENSE.** `Claude outputs/` (including the rejection-risks notes) is in the public history. |
| README with setup | Links to architecture, design, flow, runbook and real-log results at the top, with the diagram; the long file-by-file body is still there. |
| Architecture document (max 2 pages) | `docs/ARCHITECTURE.md` and the slide diagram exist. **Needs a two-page PDF**: page 1 the diagram, page 2 components and measured results. |
| Demo video (max 2 min) | **Out of date**: recorded 21 September, before the measured dashboard, real OCSF export, lossless storage, XML/CSV, real-log testing, the container and air-gap work. |
| Presentation (max 5 slides) | **Missing.** `tracelog-workflow-ppt-guide.md` is a guide, not a deck. |

## What closes the gaps, in order

1. **Deliverables** (a day's work, mostly not code): LICENSE (5 min), two-page architecture PDF (30 min),
   the five-slide deck, re-record the video on the current build.
2. **AI/ML on real traffic**: the detector is built and evaluated on synthetic days; run it on a real
   network's logs to learn its false-flag rate, and add a dashboard page listing its flags.
3. **Security baseline** (~3.5 h): API token, CORS allow-list, XSRF on, tamper endpoint behind demo mode.
4. **Signed chain checkpoints** (~2 h): the Blockchain & Cybersecurity answer.
5. **Kafka commit after store** (~1 h), then a sharded runtime and one run on multi-core hardware for the scale claim.
6. **Build the image once** with `scripts/check_image.sh`.
7. Hide Parser Studio's "Generate & Test" tab (15 min); packs for FTD 430xxx, WatchGuard, IOS, ModSecurity, Squid; retention; NetFlow/IPFIX.

## Numbers you can quote, measured today

- 17,768 real third-party log lines from 43 sources: 0 crashes, 0 invalid OCSF events, all archived and hash-chained, chain verified.
- 13,633 address and port fields checked against Elastic's own parsers: 8,693 agree; of 711 differences, all but 3 explained by evidence in the data.
- 0 wrong fields on 13 formats no parser knows (85 correct, 18 left empty); learned parsers 2,200/2,200.
- 1,818–2,427 events/s per process on 2 shared vCPUs across today's runs, 4,739 with two shards — archive, parse, OCSF and hash chain included.
- On synthetic days with eight attacks injected (3 seeds): the 6 a per-window baseline can see caught every time, 2 to 4 minutes after they began; 1 false flag a day (a nightly backup); every flag an OCSF finding in the hash chain, listing the events it came from.
- 302 tests passing; every page works with the network cut off.
