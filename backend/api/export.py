import json
import io
import csv
from fastapi import APIRouter, Response, Query
from backend.services import jsonio
from backend.services.storage.db import db
from backend.services.normalization.ocsf_export import to_ocsf

router = APIRouter(prefix="/export", tags=["Export & Integrations"])

@router.get("/ocsf-json")
def export_ocsf_json(limit: int = Query(1000, ge=1, le=5000)):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT normalized_json FROM normalized_events WHERE superseded_by IS NULL "
                       "ORDER BY sequence_num ASC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        # strict OCSF 1.1.0, exactly as the outputs send it (epoch-ms time, type_uid, finding_info, observables)
        events = [to_ocsf(jsonio.loads(r["normalized_json"])) for r in rows]
    
    json_bytes = json.dumps(events, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=tracelog_ocsf.json"}
    )

@router.get("/csv")
def export_csv(limit: int = Query(1000, ge=1, le=5000)):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT n.sequence_num, n.time, n.class_name, n.severity, n.src_ip, n.src_port,
                   n.dst_ip, n.dst_port, n.protocol, n.action, n.user_name, n.finding_title,
                   r.raw_hash, s.name as source_name
            FROM normalized_events n
            JOIN raw_logs r ON n.raw_id = r.id
            JOIN sources s ON r.source_id = s.id
            WHERE n.superseded_by IS NULL
            ORDER BY n.sequence_num ASC LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()

    output = io.StringIO()
    fieldnames = [
        "sequence_num", "time", "class_name", "severity", "src_ip", "src_port",
        "dst_ip", "dst_port", "protocol", "action", "user_name", "finding_title",
        "raw_hash", "source_name"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))

    csv_data = output.getvalue().encode("utf-8")
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tracelog_events.csv"}
    )
