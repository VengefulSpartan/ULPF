# TRACELOG against PS 26156 — requirement by requirement, with proof

Re-checked on 24 September 2026 against `main` at `4173830` (281 tests passing). Every verdict rests
on something run today: a probe against a throwaway database, a test, a measured number, or the
new real-log run. The Kafka offset fix and the pfSense service packs (OCSF 4002/4003/4004) are
already planned and are not repeated in the gap lists.

Verdicts: **Proven** (evidence a judge can rerun), **Partial** (works, with a demonstrated hole),
**Not proven** (nothing in the project shows it).

## What changed since the first audit (df3bb3b → 4173830)

| Was | Now | Evidence |
|---|---|---|
| (a) Lossless — Partial, defect proven | **Proven** | Stream: bytes reproducible and hash proves them for CRLF, Latin-1, invalid UTF-8 and padded lines (4/4). API keeps whitespace. Upload keeps `café`. |
| XML — not parsed | **Proven** | Windows 4625 → Authentication, user and source address; generic device XML → both addresses. |
| Tested only on lines we wrote | **Proven on real logs** | 17,768 third-party lines from 43 sources: 0 crashes, 0 OCSF-invalid, 17,768/17,768 archived and chained, chain verified (`docs/PUBLIC_SAMPLES.md`). |
| Cisco ASA teardown direction | **Fixed** | Real logs exposed it: outbound teardowns came *from* port 53. Now joined to the Built message. |
| Source code not pushed | **Pushed** | `origin` = github.com/VengefulSpartan/ULPF, at `8438e93`. The seven newest commits are not pushed yet. |
| (f) Correlation showed constant confidences | **Removed** | No confidence number anywhere; each relationship lists the evidence that made its rule hold (shared address, seconds apart, ports tried). The rules now check what they claimed: a login must have succeeded, an alert must be on the same address pair. |
| (j) Air-gap — Partial | **Proven** | Both servers in a network namespace with no route out, pages loaded in Chromium: 0 requests leave the machine (before: 3 — Swagger UI from a CDN, Streamlit telemetry); `/docs` renders 54 endpoints offline (before: blank). `docs/AIRGAP.md`. |
| (k) Container — Partial | **Fixed in the build files** | `.dockerignore` (planted `.env`, key, venv, notes and the database all stay out of the build context), non-root user, no compiler, one process per container, health check, read-only compose. The image itself was not built in my sandbox (Docker Hub blocked there): run `sh scripts/check_image.sh` once on your laptop. |
| CSV with a header row — not used | **Proven** | Uploads, batches and tailed files: rows read by column name through the evidence rules; 0 of 251 real log files mistaken for a header. |
| FortiGate failed logins reported as successful | **Fixed** | The pack ignored `status=failure`; found while testing correlation. |

## Expected solutions (a)–(k)

| # | The PS asks | Verdict | Proof | What is lacking |
|---|---|---|---|---|
| a | Preserve complete raw event data | **Proven** | Probe above; `tests/test_lossless.py`; `docs/adr/0002-raw-preservation.md`. | Whitespace inside HEC JSON envelopes (documented). |
| b | Extract source-specific attributes | **Proven**, coverage gaps | 12 vendor packs + CEF/LEEF. Real logs: 3,156 of 7,768 perimeter lines read by a pack, 0 crashes. | Products with many lines and no pack, where fields come out empty: **WatchGuard Firebox** (637 lines, 980 fields empty), **Cisco FTD connection events 430002/430003** (172 address fields empty), Arista NGFW (270), Squid (209), Barracuda WAF (152), Cisco IOS (87). Probe: Cisco IOS ACL, ModSecurity, Squid → no addresses. |
| c | Normalize into a common taxonomy | **Proven** | 0 OCSF-invalid on 17,768 real lines; ADR 0001. | Four classes; WAF/proxy/DNS land as Base Event. |
| d | Traceability normalized ↔ original | **Proven** | 5/5 exported events resolve to their raw line, SHA-256 matches, chain record present. | Chain unsigned and not anchored outside the database. |
| e | Plug-and-play onboarding | **Proven** | Auto-registration, setup guides, Parser Studio learn → approve without restart. | Outputs still need YAML + restart (minor). |
| f | Unified visibility | **Proven** | Every dashboard number measured from the database; correlation reports evidence, not scores. | Correlation rules are few (login then activity, allowed then alert, port sweep). |
| g | SIEM and data lake integration | **Proven** | 15 outputs, Security Lake layout + checker, dead letters, delivery ledger, reconciliation. | Kafka offsets committed before the batch is stored (planned). |
| h | AI/ML-ready analytics | **Not proven** | Schema is ML-friendly. | No feature export, no example, no baseline model. |
| i | Reduced parser effort | **Proven** | Unseen formats 85 correct, 18 missed, **0 wrong**; learned parsers 2,200/2,200. | — |
| j | Air-gapped deployment | **Proven** | Offline check above; `tests/test_airgap.py`; offline install by `docker save`/`load` or a wheelhouse in `docs/AIRGAP.md`. | — |
| k | Containerised | **Proven in files, image to be built once** | `.dockerignore`, two-stage Dockerfile, non-root, health check, hardened compose; `tests/test_container.py`. | Run `sh scripts/check_image.sh` on a machine with Docker to confirm the built image. |

## The rest of the problem statement

| The PS says | Verdict | What is lacking |
|---|---|---|
| Formats: Syslog, JSON, XML, CSV, CEF, LEEF | **Proven** | CSV with a header row now read by column name (`docs/PARSING.md`). A stored line re-parsed later in Parser Studio is read without its header. |
| Billions of events per day | **Partial** | Measured today 2,343–2,395 events/s single process on 2 vCPU (4,866 with `-w 2` earlier). 1 billion/day = 11,574/s. No sharded runtime; no run on multi-core hardware. |
| Preserving data for forensic and compliance purposes | **Partial** | No retention setting (CERT-In: 180 days); no incident-export bundle. |
| Theme: Blockchain & Cybersecurity | **Partial** | Hash chains verified, but nothing signed or anchored: anyone with database access can rebuild a consistent chain. |
| Perimeter devices incl. routers | **Partial** | NetFlow/IPFIX not received at all. |
| The framework's own security | **Not proven** | No API authentication, CORS `*`, Streamlit XSRF off, `/api/integrity/tamper` open. (The container no longer runs as root or carries secrets.) |

## Deliverables

| Deliverable | State |
|---|---|
| Source code link | Pushed to GitHub. **No LICENSE.** Repo is named ULPF, product TRACELOG. `Claude outputs/` was committed and pushed in `8438e93`, including the rejection-risks and audit notes and the old demo video. |
| README | Quickstart, measured numbers, real-log section added; body is still the long file-by-file blueprint. |
| Architecture document (2 pages) | **Missing.** |
| Demo video (2 min) | Recorded 21 Sep, before the measured dashboard, OCSF export, Security Lake, lossless, XML and real-log work. |
| Presentation (5 slides) | **Missing.** |

## What we lack — ranked

**Tier 1 — a judge can check it in two minutes**

1. Deliverables: LICENSE, push the seven new commits, 2-page architecture doc, re-record the video, the deck.
2. Build the image once with `sh scripts/check_image.sh` (a few minutes, needs Docker and internet).

Done since the first audit: lossless (a), XML, real-log testing, correlation confidences (f), container (k), air-gap (j), CSV headers.

**Tier 2 — the theme, and proof for the claims**

3. Signed chain checkpoints (Ed25519 over sequence + head, sent to the outputs as an external witness) (~2 h).
4. AI/ML-ready demo: Parquet → per-source window features → a plain statistical baseline (~2 h).
5. Security baseline: API token, CORS, XSRF on, tamper endpoint behind demo mode, receiver allow-list (~3.5 h).
6. Packs where real logs came out empty: Cisco FTD 430002/430003 connection events, WatchGuard Firebox, Cisco IOS ACL, ModSecurity, Squid (~1 h each).

**Tier 3 — completeness**

7. Retention setting and incident-export bundle (~1 h).
8. Sharded runtime and a benchmark on real multi-core hardware.
9. NetFlow/IPFIX receiver (~2–3 h).

## For the deck — measured, rerunnable claims

- Tested on **17,768 real, third-party log lines from 43 sources** (Elastic's vendor test samples for 37 perimeter products, plus Loghub): **0 crashes, 0 invalid OCSF events, every line archived and hash-chained, chain verified.**
- Cross-checked **13,633 address/port fields against Elastic's own parsers: 8,693 agree; of 711 differences, all but 3 trace to evidence in the data** — including a Cisco ASA direction error Elastic's pipeline ships and TRACELOG now fixes.
- **0 wrong fields** on 13 log formats with no parser (85 correct, 18 left empty rather than guessed).
- Every figure: `python scripts/evaluate_public_samples.py`, `scripts/evaluate_unseen_formats.py`, `scripts/benchmark.py`.
- Every page works with no internet access: 0 requests leave the machine, checked in a network namespace with no route out.
- The correlation page shows evidence, never an invented score.
