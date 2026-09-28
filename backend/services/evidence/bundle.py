"""
Evidence bundles: stored events packaged so someone outside TRACELOG can check them.

A bundle is a ZIP holding, for each chosen record:

- raw/<seq>.log      the line exactly as the device sent it (the bytes whose SHA-256 was taken
                     on arrival; the transport's line terminator, which is not part of the event,
                     is recorded in the manifest);
- events/<seq>.json  the stored OCSF event, exactly the text the chain record hashes;

and, for the bundle as a whole:

- manifest.json      where each record came from, its hashes, its chain links and, for records
                     already sealed, the Merkle inclusion proof and the signed checkpoint;
- verify.py          a standard-library checker for all of it (backend/services/evidence/verify_bundle.py);
- certificate-s63.pdf  the particulars a certificate under Section 63(4) of the Bharatiya Sakshya
                     Adhiniyam, 2023 asks for (the record, the system it came from, the hash values
                     and the algorithm), with the hash report as an annexure. It is a draft for
                     the person in charge and an expert to check, complete in the form the
                     Schedule sets out, and sign: TRACELOG does not decide admissibility;
- README.txt, SHA256SUMS.

Nothing in the archive changes: a bundle is read from the database, so the query service builds it.
"""
import hashlib
import io
import json
import secrets
import socket
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.services.integrity import checkpoints
from backend.services.storage import db as db_module

MAX_RECORDS = 5000
IST = timezone(timedelta(hours=5, minutes=30))
VERIFY_SCRIPT = Path(__file__).with_name("verify_bundle.py")


class EvidenceError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw_bytes(row) -> bytes:
    if row["raw_hash_of"] == "bytes":
        return row["raw_text"].encode(row["raw_encoding"] or "utf-8")
    return row["raw_text"].encode("utf-8")


def ist(iso_or_dt) -> str:
    """'21/09/2026 15:50:12 IST' from an ISO time or a datetime (UTC assumed when naive)."""
    if not iso_or_dt:
        return ""
    dt = iso_or_dt if isinstance(iso_or_dt, datetime) else datetime.fromisoformat(str(iso_or_dt).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime("%d/%m/%Y %H:%M:%S IST")


def incident_sequences(incident_id: str) -> Dict[str, Any]:
    with db_module.db.get_connection() as conn:
        row = conn.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise EvidenceError(f"no incident {incident_id}")
    data = json.loads(row[0])
    seqs = [f["sequence_num"] for f in data.get("observed_facts") or []]
    return {"sequences": seqs, "title": data.get("title"), "incident_id": incident_id}


_RECORDS = """
SELECT l.sequence_num, l.event_id, l.raw_id, l.raw_hash, l.record_hash, l.prev_hash, l.timestamp AS chained_at,
       n.normalized_json, n.time AS event_time, n.class_name, n.severity, n.src_ip, n.dst_ip, n.finding_title,
       n.superseded_by,
       r.raw_text, r.raw_encoding, r.raw_hash_of, r.raw_framing, r.transport, r.input_name, r.peer_ip,
       r.received_at, r.ingested_at, r.format_detected,
       s.name AS source_name, s.vendor, s.product
FROM integrity_ledger l
JOIN normalized_events n ON n.id = l.event_id
JOIN raw_logs r ON r.id = l.raw_id
LEFT JOIN sources s ON s.id = r.source_id
WHERE l.sequence_num IN ({marks})
ORDER BY l.sequence_num
"""


def collect(sequences: List[int]) -> Dict[str, Any]:
    """Everything a bundle needs about these records, read in one go."""
    seqs = sorted({int(s) for s in sequences})
    if not seqs:
        raise EvidenceError("choose at least one record")
    if len(seqs) > MAX_RECORDS:
        raise EvidenceError(f"at most {MAX_RECORDS} records per bundle; {len(seqs)} were chosen")
    with db_module.db.get_connection() as conn:
        rows = []
        for i in range(0, len(seqs), 900):          # SQLite's limit on bound parameters
            part = seqs[i:i + 900]
            rows += [dict(r) for r in conn.execute(_RECORDS.format(marks=",".join("?" * len(part))), part)]
        missing = sorted(set(seqs) - {r["sequence_num"] for r in rows})
        proofs = {r["sequence_num"]: checkpoints.proof(r["sequence_num"], conn) for r in rows}
        head = conn.execute("SELECT sequence_num, record_hash FROM integrity_ledger ORDER BY sequence_num DESC LIMIT 1"
                            ).fetchone()
        log = checkpoints.log_id(conn)
    if missing:
        raise EvidenceError(f"no chain record #{', #'.join(map(str, missing[:10]))}")
    return {"rows": rows, "proofs": proofs, "head": tuple(head) if head else (0, checkpoints.GENESIS), "log_id": log}


def build(sequences: List[int], case: Optional[Dict[str, str]] = None, scope: Optional[Dict[str, Any]] = None,
          with_certificate: bool = True) -> Dict[str, Any]:
    """The bundle as ZIP bytes, with its id, file name and manifest."""
    case = {k: (v or "").strip() for k, v in (case or {}).items()}
    got = collect(sequences)
    now = datetime.now(timezone.utc)
    bundle_id = f"EV-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2).upper()}"
    files: Dict[str, bytes] = {}
    records, cps, checks = [], {}, {"raw_hash_matches": 0, "record_hash_matches": 0, "in_signed_checkpoint": 0}
    for row in got["rows"]:
        seq = row["sequence_num"]
        raw = _raw_bytes(row)
        event = row["normalized_json"].encode("utf-8")
        raw_file, event_file = f"raw/{seq:08d}.log", f"events/{seq:08d}.json"
        files[raw_file], files[event_file] = raw, event
        checks["raw_hash_matches"] += _sha(raw) == row["raw_hash"]
        preimage = f"{row['prev_hash']}:{seq}:{row['raw_hash']}:{row['normalized_json'].strip()}"
        checks["record_hash_matches"] += _sha(preimage.encode("utf-8")) == row["record_hash"]
        proof = got["proofs"].get(seq)
        rec_proof = None
        if proof:
            cp = proof["checkpoint"]
            cps[str(cp["index"])] = {"body": cp["body"], "checkpoint_hash": cp["checkpoint_hash"],
                                     "signatures": cp["signatures"]}
            rec_proof = {"checkpoint": cp["index"], "leaf_index": proof["leaf_index"], "tree_size": proof["tree_size"],
                         "path": proof["path"]}
            checks["in_signed_checkpoint"] += 1
        records.append({
            "sequence_num": seq, "event_id": row["event_id"], "raw_id": row["raw_id"],
            "source": row["source_name"], "vendor": row["vendor"], "product": row["product"],
            "received_at": row["received_at"] or row["ingested_at"], "transport": row["transport"],
            "input": row["input_name"], "sender_ip": row["peer_ip"], "format": row["format_detected"],
            "event_time": row["event_time"], "class_name": row["class_name"], "severity": row["severity"],
            "src_ip": row["src_ip"], "dst_ip": row["dst_ip"], "finding": row["finding_title"],
            "raw_file": raw_file, "raw_sha256": row["raw_hash"],
            "raw_sha256_of": "the bytes as received" if row["raw_hash_of"] == "bytes" else "the line's UTF-8 text",
            "line_terminator_removed": row["raw_framing"] or "none",
            "event_file": event_file, "prev_hash": row["prev_hash"], "record_hash": row["record_hash"],
            "chained_at": row["chained_at"], "superseded_by": row["superseded_by"], "proof": rec_proof,
        })
    witnessed = sorted({s.get("name") for c in cps.values() for s in c["signatures"] if s.get("role") == "witness"})
    manifest = {
        "bundle": {"id": bundle_id, "created_at": now.isoformat(timespec="seconds"), "created_at_ist": ist(now),
                   "created_by": f"TRACELOG {settings.VERSION}", "host": socket.gethostname(),
                   "log_id": got["log_id"], "case": case, "scope": scope or {"kind": "records"}},
        "hash_algorithm": "SHA-256",
        "chain_head_at_export": {"sequence_num": got["head"][0], "record_hash": got["head"][1]},
        "records": records,
        "checkpoints": cps,
        "checks_at_export": {"records": len(records), **checks, "checkpoints": len(cps),
                             "witnesses": witnessed},
        "how_to_check": "Run `python verify.py` in this folder (Python 3.8+). `sha256sum -c SHA256SUMS` checks the "
                        "files alone. Signatures are checked when the cryptography package is installed.",
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    files["manifest.json"] = manifest_bytes
    files["verify.py"] = VERIFY_SCRIPT.read_bytes()
    files["README.txt"] = _readme(manifest, _sha(manifest_bytes)).encode("utf-8")
    if with_certificate:
        from backend.services.evidence.certificate_pdf import render_certificate
        files["certificate-s63.pdf"] = render_certificate(manifest, _sha(manifest_bytes))
    sums = "".join(f"{_sha(data)}  {name}\n" for name, data in sorted(files.items()))
    files["SHA256SUMS"] = sums.encode("ascii")

    buf = io.BytesIO()
    root = f"TRACELOG-evidence-{bundle_id}"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=now.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name == "verify.py" else 0o644) << 16
            z.writestr(info, files[name])
    return {"id": bundle_id, "filename": f"{root}.zip", "zip": buf.getvalue(), "manifest_sha256": _sha(manifest_bytes),
            "records": len(records), "checks": manifest["checks_at_export"]}


def _readme(manifest: Dict[str, Any], manifest_sha: str) -> str:
    b, c = manifest["bundle"], manifest["checks_at_export"]
    recs = manifest["records"]
    sources = sorted({r["source"] or "unknown" for r in recs})
    return f"""TRACELOG evidence bundle {b['id']}
Created {b['created_at']} UTC ({b['created_at_ist']}) by {b['created_by']} on {b['host']}.

What is inside
  raw/              {len(recs)} log line(s), byte for byte as the device sent them
  events/           the stored OCSF event for each line, exactly as it was hash-chained
  manifest.json     where each line came from, its SHA-256, its chain record and its proofs
  verify.py         checks all of it: python verify.py
  certificate-s63.pdf  particulars and hash report for a certificate under Section 63(4),
                    Bharatiya Sakshya Adhiniyam, 2023 (a draft: to be checked, completed and signed)
  SHA256SUMS        the SHA-256 of every file above (sha256sum -c SHA256SUMS)

manifest.json SHA-256: {manifest_sha}

Records: #{recs[0]['sequence_num']} to #{recs[-1]['sequence_num']} ({len(recs)} in all), from {', '.join(sources)}.
At export: {c['raw_hash_matches']} of {c['records']} raw lines matched their SHA-256, {c['record_hash_matches']} chain
records matched their hash, {c['in_signed_checkpoint']} were in a signed checkpoint
({len(manifest['checkpoints'])} checkpoint(s){', witnessed by ' + ', '.join(c['witnesses']) if c['witnesses'] else ''}).

What this proves, and what it does not
  The lines and events are the ones TRACELOG received and chained, unchanged since. Records in a
  signed checkpoint are also covered by the node's signature and any witnesses' signatures, which
  someone with access to the database alone cannot forge. It does not prove that a device logged
  the truth or logged everything.
"""
