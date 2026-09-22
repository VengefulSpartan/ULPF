"""
Re-parse history with a newly approved parser, as chained revisions.

Lines that arrived before a parser existed were archived byte-for-byte and parsed by the
generic parser, which left fields empty rather than guess. Once a person approves a learned
parser for their format, those lines are parsed again:

  - the archived line and the original event's hashed record are never changed or deleted:
    the original stays in the integrity chain;
  - the new parse is appended to the chain as a new event for the same raw line, carrying
    unmapped.tracelog_revision = {supersedes, supersedes_sequence, revision, parser_id,
    parser, approved_by, reason};
  - event_revisions records the link, and the original row's superseded_by column (an index,
    not part of the hashed record) points to it, so searches and dashboards show the
    current version;
  - revisions are routed to the configured outputs like any new event, so SIEMs receive
    the corrected fields, with the uid of the event they replace.

Running it twice changes nothing: lines whose current event already came from this parser
are skipped.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.services.ingestion.stream import store_event
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parser_generation import learned
from backend.services.parsing.dispatch import parse_log
from backend.services.storage import db as db_module

logger = logging.getLogger("tracelog.reparse")

BATCH = 500
CARRY = ("transport", "sender_ip", "device_hostname")


def reparse_history(parser_id: str, reason: Optional[str] = None, limit: Optional[int] = None,
                    route: bool = True) -> Dict[str, Any]:
    database = db_module.db
    with database.get_connection() as conn:
        row = conn.execute("SELECT name, status, approved_by FROM parsers WHERE id = ? AND format_type = 'learned'",
                           (parser_id,)).fetchone()
    if not row:
        raise ValueError(f"no learned parser {parser_id}")
    if row["status"] != "approved":
        raise ValueError(f"parser {parser_id} is {row['status']}: only an approved parser re-parses history")
    learned.invalidate()
    reason = reason or f"re-parsed with learned parser '{row['name']}' approved by {row['approved_by']}"
    stats = {"examined": 0, "revised": 0, "unchanged": 0, "failed": 0, "first_sequence": None, "last_sequence": None}
    after = 0
    while limit is None or stats["revised"] < limit:
        routed: List[Tuple[Dict[str, Any], str]] = []
        with IntegrityLedger.write_lock, database.get_connection() as conn:
            rows = conn.execute(
                "SELECT r.id AS raw_id, r.raw_text, r.raw_hash, r.source_id, n.id AS event_id, n.sequence_num, "
                "n.unmapped_json FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id "
                "WHERE n.superseded_by IS NULL AND r.format_detected = 'generic_inferred' AND n.sequence_num > ? "
                "AND NOT EXISTS (SELECT 1 FROM event_revisions v WHERE v.event_id = n.id AND v.parser_id = ?) "
                "ORDER BY n.sequence_num LIMIT ?", (after, parser_id, BATCH)).fetchall()
            if not rows:
                break
            for r in rows:
                after = r["sequence_num"]
                if limit is not None and stats["revised"] >= limit:
                    break
                stats["examined"] += 1
                try:
                    _, parsed = parse_log(r["raw_text"])
                except Exception:
                    logger.exception("re-parse failed for raw %s", r["raw_id"])
                    stats["failed"] += 1
                    continue
                if (parsed.get("tracelog_parse") or {}).get("parser_id") != parser_id:
                    stats["unchanged"] += 1
                    continue
                normalized = _revise(conn, r, parsed, parser_id, row, reason)
                stats["revised"] += 1
                stats["first_sequence"] = stats["first_sequence"] or normalized["metadata"]["sequence_num"]
                stats["last_sequence"] = normalized["metadata"]["sequence_num"]
                routed.append((normalized, r["source_id"]))
            conn.commit()
        if route and routed:
            try:
                from backend.connectors.engine import engine
                for normalized, source_id in routed:
                    engine.route_normalized(normalized, source_id)
            except Exception:
                logger.exception("could not hand revisions to the outputs")
    return stats


def _revise(conn, r, parsed: Dict[str, Any], parser_id: str, parser_row, reason: str) -> Dict[str, Any]:
    latest = IntegrityLedger.get_latest_entry(conn)
    seq = (latest["sequence_num"] + 1) if latest else 1
    event_id = str(uuid.uuid4())
    ev = OCSFNormalizer.normalize(parsed, r["raw_text"], r["raw_id"], r["raw_hash"],
                                  vendor=parsed.get("vendor") or "Generic", product=parsed.get("product") or "Device",
                                  sequence_num=seq)
    ev.id = event_id
    old = json.loads(r["unmapped_json"] or "{}")
    for key in CARRY:
        if key in old and key not in ev.unmapped:
            ev.unmapped[key] = old[key]
    revision = conn.execute("SELECT COUNT(*) FROM event_revisions WHERE raw_id = ?", (r["raw_id"],)).fetchone()[0] + 1
    ev.unmapped["tracelog_revision"] = {
        "supersedes": r["event_id"], "supersedes_sequence": r["sequence_num"], "revision": revision,
        "parser_id": parser_id, "parser": parser_row["name"], "approved_by": parser_row["approved_by"],
        "reason": reason}
    normalized = store_event(conn, ev, event_id, seq, r["raw_id"], r["raw_hash"])
    conn.execute(
        "INSERT INTO event_revisions (event_id, sequence_num, supersedes_event_id, supersedes_sequence, raw_id, "
        "parser_id, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (event_id, seq, r["event_id"], r["sequence_num"], r["raw_id"], parser_id, reason,
         datetime.now(timezone.utc).isoformat()))
    conn.execute("UPDATE normalized_events SET superseded_by = ? WHERE id = ?", (event_id, r["event_id"]))
    return normalized


def revision_check(conn) -> Dict[str, Any]:
    """Every superseded event must point to a chained revision that names it, and vice versa."""
    revisions = conn.execute("SELECT COUNT(*) FROM event_revisions").fetchone()[0]
    superseded = conn.execute("SELECT COUNT(*) FROM normalized_events WHERE superseded_by IS NOT NULL").fetchone()[0]
    broken = conn.execute(
        "SELECT COUNT(*) FROM normalized_events o LEFT JOIN event_revisions v ON v.event_id = o.superseded_by "
        "LEFT JOIN normalized_events n ON n.id = v.event_id "
        "WHERE o.superseded_by IS NOT NULL AND (v.event_id IS NULL OR v.supersedes_event_id != o.id "
        "OR n.id IS NULL OR json_extract(n.unmapped_json, '$.tracelog_revision.supersedes') != o.id)").fetchone()[0]
    return {"revisions": revisions, "superseded": superseded, "broken_links": broken,
            "consistent": revisions == superseded and broken == 0}
