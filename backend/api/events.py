import json
import re
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from backend.services.storage.db import db

router = APIRouter(prefix="/events", tags=["Log Explorer & Events"])

# a word, address, hostname or user name: what the full-text index can look up directly
FTS_TOKEN = re.compile(r"[\w.:/@-]{2,64}")


def _has_search_index(conn) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'raw_search'").fetchone())

@router.get("")
def list_events(
    search: Optional[str] = None,
    source_id: Optional[str] = None,
    severity: Optional[str] = None,
    class_name: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_superseded: bool = Query(False, description="also list events replaced by a re-parse")
):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        query = """
        SELECT n.*, r.raw_text, r.raw_hash, r.format_detected, s.name as source_name, s.vendor, s.product
        FROM normalized_events n
        JOIN raw_logs r ON n.raw_id = r.id
        JOIN sources s ON r.source_id = s.id
        WHERE 1=1
        """
        params = []
        current = "" if include_superseded else " AND n.superseded_by IS NULL"
        query += current

        if search:
            token = FTS_TOKEN.fullmatch(search.strip())
            if token and _has_search_index(conn):
                # the archived lines are in a full-text index, so this is a lookup rather than a
                # scan of every stored line. "10.0.1.15" is matched as a phrase (the tokenizer
                # splits on the dots) and as a prefix, so "explo" still finds "exploit". It
                # searches the archived line, which is where the values come from; the boxes
                # beside it filter on the OCSF fields.
                term = search.strip().replace('"', '""')
                query += " AND r.rowid IN (SELECT rowid FROM raw_search WHERE raw_search MATCH ?)"
                params.append(f'"{term}"*')
            else:
                query += " AND (r.raw_text LIKE ? OR n.normalized_json LIKE ?)"
                term = f"%{search}%"
                params.extend([term, term])
        
        if source_id:
            query += " AND r.source_id = ?"
            params.append(source_id)

        if severity:
            query += " AND n.severity = ?"
            params.append(severity)

        if class_name:
            query += " AND n.class_name = ?"
            params.append(class_name)

        if ip:
            query += " AND (n.src_ip = ? OR n.dst_ip = ?)"
            params.extend([ip, ip])

        query += " ORDER BY n.sequence_num DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        events = []
        for r in rows:
            events.append({
                "id": r["id"],
                "sequence_num": r["sequence_num"],
                "raw_id": r["raw_id"],
                "class_name": r["class_name"],
                "severity": r["severity"],
                "severity_id": r["severity_id"],
                "time": r["time"],
                "src_ip": r["src_ip"],
                "src_port": r["src_port"],
                "dst_ip": r["dst_ip"],
                "dst_port": r["dst_port"],
                "protocol": r["protocol"],
                "action": r["action"] or r["disposition"],
                "user_name": r["user_name"],
                "finding_title": r["finding_title"],
                "raw_text": r["raw_text"],
                "raw_hash": r["raw_hash"],
                "format_detected": r["format_detected"],
                "source_name": r["source_name"],
                "vendor": r["vendor"],
                "product": r["product"],
                "normalized": json.loads(r["normalized_json"]),
                "unmapped": json.loads(r["unmapped_json"]) if r["unmapped_json"] else {},
                "superseded_by": r["superseded_by"]
            })

        # Total count. The index is named on purpose: left to its own statistics SQLite reads every
        # row of the table for this (108 ms at 100k events), while counting the partial index of
        # current events takes about a millisecond.
        if current:
            try:
                cursor.execute("SELECT COUNT(*) FROM normalized_events n INDEXED BY idx_norm_events_current "
                               "WHERE 1=1" + current)
            except Exception:  # a database from before that index existed
                cursor.execute("SELECT COUNT(*) FROM normalized_events n WHERE 1=1" + current)
        else:
            cursor.execute("SELECT COUNT(*) FROM normalized_events")
        total_count = cursor.fetchone()[0]

        return {
            "total": total_count,
            "count": len(events),
            "limit": limit,
            "offset": offset,
            "events": events
        }

@router.get("/{event_id}")
def get_event_detail(event_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT n.*, r.raw_text, r.raw_hash, r.format_detected, s.name as source_name, s.vendor, s.product,
                   l.record_hash, l.prev_hash
            FROM normalized_events n
            JOIN raw_logs r ON n.raw_id = r.id
            JOIN sources s ON r.source_id = s.id
            LEFT JOIN integrity_ledger l ON n.id = l.event_id
            WHERE n.id = ?
            """,
            (event_id,)
        )
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Event not found")

        return {
            "id": r["id"],
            "sequence_num": r["sequence_num"],
            "raw_id": r["raw_id"],
            "class_name": r["class_name"],
            "severity": r["severity"],
            "time": r["time"],
            "src_ip": r["src_ip"],
            "src_port": r["src_port"],
            "dst_ip": r["dst_ip"],
            "dst_port": r["dst_port"],
            "protocol": r["protocol"],
            "action": r["action"] or r["disposition"],
            "superseded_by": r["superseded_by"],
            "user_name": r["user_name"],
            "raw_text": r["raw_text"],
            "raw_hash": r["raw_hash"],
            "record_hash": r["record_hash"],
            "prev_hash": r["prev_hash"],
            "format_detected": r["format_detected"],
            "source_name": r["source_name"],
            "vendor": r["vendor"],
            "product": r["product"],
            "normalized": json.loads(r["normalized_json"]),
            "unmapped": json.loads(r["unmapped_json"]) if r["unmapped_json"] else {}
        }
