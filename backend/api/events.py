import json
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from backend.services.storage.db import db

router = APIRouter(prefix="/events", tags=["Log Explorer & Events"])

@router.get("")
def list_events(
    search: Optional[str] = None,
    source_id: Optional[str] = None,
    severity: Optional[str] = None,
    class_name: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
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

        if search:
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
                "unmapped": json.loads(r["unmapped_json"]) if r["unmapped_json"] else {}
            })

        # Total count
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
