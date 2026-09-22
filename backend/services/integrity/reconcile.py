"""
Reconciliation: proves every stored log line is accounted for, from archive to each destination.

Pipeline:   raw lines archived  =  normalised OCSF events  =  hash-chain records, chain verified
Per output: owed = delivered + delivered through another output + excluded by filter
                 + waiting in dead letters + in flight
            and anything left over is "unaccounted" (the number that must be zero).

"Owed" means stored events from the moment the output was first configured. The same data
feeds the dashboard's Reconcile view and the downloadable audit report, whose fingerprint
(report SHA-256 plus the head hashes of both ledgers) lets anyone check it later.
"""
import hashlib
import json
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.services.integrity.delivery_ledger import DeliveryLedger
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.storage import db as db_module


def _iso(ms: Optional[int]) -> Optional[str]:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat() if ms else None


def _pipeline() -> Dict[str, Any]:
    with db_module.db.get_connection() as conn:
        raw = conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
        normalized = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        chained = conn.execute("SELECT COUNT(*) FROM integrity_ledger").fetchone()[0]
        lo, hi, max_seq = conn.execute(
            "SELECT MIN(time_epoch_ms), MAX(time_epoch_ms), MAX(sequence_num) FROM normalized_events").fetchone()
        head = conn.execute("SELECT record_hash FROM integrity_ledger ORDER BY sequence_num DESC LIMIT 1").fetchone()
        from backend.services.parser_generation.reparse import revision_check
        revisions = revision_check(conn)
        streamed = conn.execute("SELECT COUNT(*) FROM raw_logs WHERE transport IS NOT NULL").fetchone()[0]
        sources = [dict(r) for r in conn.execute(
            "SELECT name, vendor, product, category, event_count, last_event_at FROM sources "
            "WHERE event_count > 0 ORDER BY event_count DESC")]
    originals = normalized - revisions["revisions"]
    # every archived line has one original event; re-parses add chained revisions of those lines
    return {"raw_archived": raw, "normalized": normalized, "original_events": originals,
            "revisions": revisions["revisions"], "revisions_consistent": revisions["consistent"],
            "hash_chained": chained, "streamed": streamed,
            "uploaded_or_api": raw - streamed, "max_sequence": max_seq or 0,
            "period": {"first_event": _iso(lo), "last_event": _iso(hi)},
            "integrity_head": head[0] if head else None, "sources": sources,
            "consistent": raw == originals and normalized == chained and revisions["consistent"]}


def reconcile(verify: bool = True) -> Dict[str, Any]:
    from backend.connectors.engine import engine  # late import: the engine imports this package

    pipe = _pipeline()
    upto = pipe["max_sequence"]
    sinks = {s.cfg.name: s for s in engine.sinks}
    stores = engine.dead_letter_stores()
    outputs: List[Dict[str, Any]] = []
    for reg in DeliveryLedger.outputs():
        name = reg["output"]
        c = DeliveryLedger.output_counts(name, reg["first_seq"], upto)
        sink = sinks.get(name)
        in_flight = (sink.queue.qsize() + sink.in_flight) if sink else 0
        in_flight = min(in_flight, c["without_outcome"])
        unaccounted = c["without_outcome"] - in_flight
        dl_file = stores[name].summary()["waiting"] if name in stores else 0
        notes = []
        if dl_file != c["dead_letter_waiting"]:
            notes.append(f"dead-letter file holds {dl_file} entries, ledger says {c['dead_letter_waiting']}")
        if c["duplicates"]:
            notes.append(f"{c['duplicates']} events were delivered more than once (at-least-once re-sends)")
        if not sink:
            notes.append("not in the current configuration")
        outputs.append({
            "output": name, "type": reg.get("type"), "target": reg.get("target"), "configured": bool(sink),
            "owed_from_sequence": reg["first_seq"], "added_at": reg["added_at"], **c,
            "in_flight": in_flight, "unaccounted": unaccounted, "dead_letter_file_entries": dl_file,
            "status": "balanced" if unaccounted == 0 else "unaccounted events", "notes": notes})

    integrity = IntegrityLedger.verify_chain().model_dump() if verify else None
    delivery = DeliveryLedger.verify() if verify else None
    problems = []
    if not pipe["consistent"]:
        problems.append("archive, normalised events, re-parse revisions and hash chain do not add up")
    if integrity is not None and not integrity["is_valid"]:
        problems.append(f"integrity chain failed verification ({integrity['failed_records']} records)")
    if delivery is not None and not delivery["is_valid"]:
        problems.append(f"delivery ledger failed verification ({delivery['issue_count']} issues)")
    for o in outputs:
        if o["unaccounted"]:
            problems.append(f"{o['unaccounted']} events unaccounted for at {o['output']}")
    waiting = sum(o["dead_letter_waiting"] for o in outputs)
    in_flight = sum(o["in_flight"] for o in outputs)
    if problems:
        verdict = "; ".join(problems)
    else:
        verdict = f"All {pipe['normalized']:,} stored events are accounted for at every output."
        if waiting or in_flight:
            verdict += f" {waiting:,} wait in dead letters and {in_flight:,} are in flight, all recorded."
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "all_accounted": not problems, "verdict": verdict, "problems": problems,
        "pipeline": {k: v for k, v in pipe.items() if k not in ("sources", "integrity_head")},
        "live": {k: engine.metrics.get(k) for k in ("received", "ingested", "spooled", "replayed", "started_at")},
        "integrity": integrity, "delivery_ledger": delivery, "outputs": outputs,
        "dead_letters": [d for d in engine.dead_letters() if d.get("waiting")],
        "exceptions": DeliveryLedger.exceptions(25), "sources": pipe["sources"],
        "recovery": engine.recovery,
        "heads": {"integrity": pipe["integrity_head"], "delivery": (delivery or {}).get("head_hash")},
    }


def audit_report() -> Dict[str, Any]:
    """The reconciliation plus identity and a fingerprint anyone can recompute."""
    body = reconcile(verify=True)
    body = {"report": "TRACELOG log delivery audit", "report_id": uuid.uuid4().hex[:12].upper(),
            "host": socket.gethostname(), **body}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    body["fingerprint"] = {
        "report_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "integrity_chain_head": body["heads"]["integrity"],
        "delivery_ledger_head": body["heads"]["delivery"],
        "how_to_check": "report_sha256 is SHA-256 of this JSON without the 'fingerprint' key, serialised with "
                        "sorted keys and no spaces. The two head hashes must still be present in TRACELOG's "
                        "ledgers (GET /api/integrity/ledger, GET /api/audit/delivery/verify); if either chain "
                        "was rewritten after this report, they will not match.",
    }
    return body
