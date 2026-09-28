# Evidence: signed checkpoints, witnesses, evidence bundles and CERT-In mode

The hash chain ([SYSTEM_DESIGN.md](SYSTEM_DESIGN.md)) proves a stored record was not changed, removed or
reordered, as long as whoever changed it did not also recompute the chain. This document covers the three
things built on top of it so that the logs hold up outside TRACELOG: in an audit, in a court, and in a
report to CERT-In.

| What | Where in the code | What it adds |
| :--- | :--- | :--- |
| Signed checkpoints | `backend/services/integrity/checkpoints.py`, `merkle.py`, `signing.py` | A Merkle root over every 1,000 records, signed by the collector with Ed25519 and ML-DSA-65 |
| Witnesses | `backend/witness.py` | Separate services that countersign each checkpoint and never sign two different ones with the same number |
| Evidence bundles | `backend/services/evidence/` | A ZIP anyone can check with `python verify.py`, with the particulars a Section 63(4) certificate asks for |
| CERT-In mode | `backend/services/compliance/` | 180-day retention status, no deletion, and incident report drafts with the 6-hour deadline |

## 1. Signed checkpoints

Every `CHECKPOINT_SIZE` records (1,000 by default) the one writer seals the records not yet covered, inside
the same transaction as the batch that completed the window. A timer in the collector seals whatever is
left every `CHECKPOINT_EVERY_SECONDS` (300), and **Seal now** on the Integrity page does it on request.

A checkpoint is a small canonical JSON body:

```json
{"v": 1, "type": "tracelog-checkpoint", "log_id": "…", "index": 33, "first_seq": 32001, "last_seq": 32300,
 "size": 300, "merkle_root": "267aa103…", "prev_checkpoint": "<hash of checkpoint 32>",
 "node_key_id": "bd9793f580de2d20", "sealed_at": "2026-09-27T23:44:21+00:00"}
```

- **The Merkle tree is RFC 9162's** (Certificate Transparency 2.0): leaves and inner nodes are hashed with
  different prefixes, and the leaf for a record is `"<sequence number>:<record hash>"`. The record hash
  already covers the raw line's SHA-256 and the stored event, so the root covers both. The test suite
  checks the roots against RFC 6962's reference values.
- **Checkpoints form their own chain.** Each names the previous one's hash, so checkpoint 33 commits to all
  32,300 records before it.
- **Two signatures per signer.** Ed25519, and ML-DSA-65 (FIPS 204, designed to resist quantum computers)
  where the installed `cryptography` supports it (version 47 and later). Each signature records its
  algorithm, so another one can be added later without touching what is already signed.
- **Keys** are created on first use in `keys/` next to the database (or `TRACELOG_KEY_DIR`), readable by the
  service's user only. `data/keys/` is in `.gitignore` and `*.pem` in `.dockerignore`.
- **Size:** a checkpoint with three signers (the node and two witnesses, each Ed25519 plus ML-DSA-65 with its
  public key) is about 23 KB: about 23 bytes per record at 1,000 records a checkpoint, and the timer adds at
  most 288 a day. ML-DSA signatures are large (3,309 bytes each); that is the price of the post-quantum one.
- **Cost:** sealing inline measured within run-to-run noise on `scripts/benchmark.py -n 20000 -b 1000`
  (2,893 and 2,942 events/s with sealing, 2,959 and 2,736 without). Verifying 33 checkpoints over 32,300
  records takes about 0.1 s; an inclusion proof, about 4 ms.

`GET /api/integrity/checkpoints` recomputes every root from the records as they are now, checks every link
and signature, and asks the witnesses what they signed. `GET /api/integrity/proof/{seq}` returns the
inclusion proof of one record.

## 2. Witnesses

The chain and the node's signatures cannot stop an insider who has both the database and the collector's
keys: they can change a record, recompute every hash after it and re-sign the checkpoints. A witness is
what that insider does not control.

A witness (`uvicorn backend.witness:app`, `WITNESS_ID`, `WITNESS_DATA_DIR`) keeps its own keys and its own
SQLite file of what it signed. It signs checkpoint N of a log only if

1. the node's signature is valid, by the node key it first saw for that log (pinned from then on);
2. N is the next number, and it has signed nothing else numbered N;
3. the checkpoint names, as its previous one, the checkpoint N-1 this witness signed.

Asked to sign anything else, it answers 409 and says why. The collector sends each new checkpoint to every
witness in `WITNESS_URLS` on the timer; verification reads back what each witness signed and reports any
checkpoint where their copies and the archive differ.

**Where they run.** Docker Compose starts `witness-1` and `witness-2` beside the collector, each with its
own volume, and `python run_app.py` starts two on ports 8101 and 8102 with their records in
`data/witness-1` and `data/witness-2`. That shows the mechanism. The protection comes from running them on
machines the collector's administrators do not control (another team's server, another site), since a
witness on the same host shares its fate.

**Resetting the archive** (Settings, single laptop only) starts a new log: the witnesses keep what they
signed for the old one.

### The demonstration

Integrity page, **Tamper test**, *An insider with the server's keys*, **Rewrite history**:

1. the record's disposition changes, every record hash after it is recomputed and the affected checkpoints
   are resealed and re-signed with the node's key;
2. **Verify the chain** says *Intact*: the chain alone is fooled;
3. the witnesses have already refused the rewritten checkpoint (*"checkpoint #33 of this log was already
   signed with hash 99f25be5…; refusing a different one"*);
4. **Check the checkpoints** says *Problem at #33* and *0 of 2 agree*;
5. **Restore history** puts every hash and checkpoint back.

The *Someone with database access* option is the older demonstration: one record changed without
recomputing anything, caught by the chain itself.

## 3. Evidence bundles

**Evidence bundle** on Log Explorer (one event, or the events shown) and on Correlation (every event of the
incident), or `GET /api/evidence/bundle.zip?seq=…&seq=…` / `?incident_id=…`. The ZIP holds:

| File | What it is |
| :--- | :--- |
| `raw/<seq>.log` | the line exactly as the device sent it: the bytes whose SHA-256 was taken on arrival |
| `events/<seq>.json` | the stored OCSF event, exactly the text its chain record hashes |
| `manifest.json` | where each record came from, its hashes and links, and for sealed records the Merkle proof and the signed checkpoint with every signature |
| `verify.py` | checks all of it with the Python standard library; signatures too when `cryptography` is installed |
| `certificate-s63.pdf` | the particulars for a certificate under Section 63(4), Bharatiya Sakshya Adhiniyam, 2023, with the hash report as an annexure |
| `README.txt`, `SHA256SUMS` | what is inside; the SHA-256 of every file (`sha256sum -c SHA256SUMS`) |

`python verify.py` prints one line per check and exits 0 when everything that could be checked holds;
change one byte of a raw line and it names the record. The bundle is read from the database only, so the
read-only query service builds it.

**The certificate particulars are a draft.** The Adhiniyam's Schedule sets out the certificate: Part A by
the party producing the record, Part B by an expert, each naming the source, the hash values and the
algorithm, signed with date, time (IST) and place. The PDF fills in what TRACELOG knows (the record, the
system it came from, every SHA-256, how to check them) and leaves blank what only the signatories can
state. It says so on its first page. Whether a record is admitted is for the court.

## 4. CERT-In mode

The CERT-In directions of 28 April 2022 ask for logs kept for a rolling 180 days within India, cyber
incidents reported within 6 hours of being noticed (to incident@cert-in.org.in, with the CERT-In incident
reporting form), and clocks synchronised to NIC or NPL time servers.

`CERTIN_MODE=true`:

- **Settings** shows the days of logs held against `RETENTION_DAYS` (180), successful and failed events
  (both are kept), and where the archive is kept as the operator declares it (`DATA_LOCATION`; TRACELOG
  cannot check it);
- stored events cannot be deleted from the dashboard (TRACELOG never deletes a line on its own);
- **CERT-In report draft** on Correlation (or `GET /api/compliance/certin/report.pdf|.json?incident_id=…`)
  drafts what the report needs: the Annexure I type, suggested from the evidence with the reason and
  confirmed by a person; when it was noticed (the first detection TRACELOG received) and when the 6-hour
  window closes; the internal addresses, users and devices involved; external addresses and signatures as
  indicators; the timeline with each raw line's SHA-256; the correlation rules that matched, with their
  limits; and the evidence kept, checked against its hashes.

TRACELOG sends nothing to CERT-In. The draft is for a person to check, complete and send.

## 5. What this does not prove

- That a device logged the truth, or logged everything: every layer starts at the moment TRACELOG receives
  a line.
- That records written after the last checkpoint are untouched by someone with the node's keys: they are
  covered by the chain, and by the next checkpoint within five minutes (or at once, with **Seal now**).
- Anything, if the witnesses run on the same machine as the collector and the whole machine is
  compromised.
