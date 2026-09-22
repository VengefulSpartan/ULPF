from fastapi import APIRouter
from backend.services.storage.db import db
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.analytics.quality import ocsf_conformance, parse_breakdown, pipeline_counts

router = APIRouter(prefix="/analytics", tags=["Analytics & Operational KPIs"])

@router.get("/overview")
def get_overview_kpis():
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Total events
        cursor.execute("SELECT COUNT(*) FROM normalized_events WHERE superseded_by IS NULL")
        total_events = cursor.fetchone()[0]

        # 2. Active sources
        cursor.execute("SELECT COUNT(*) FROM sources WHERE is_active = 1")
        active_sources = cursor.fetchone()[0]

        # 3. Parsers count & approved count
        cursor.execute("SELECT COUNT(*) FROM parsers")
        total_parsers = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM parsers WHERE status = 'approved'")
        approved_parsers = cursor.fetchone()[0]

        # 4. Events by category
        cursor.execute("SELECT category_name, COUNT(*) as cnt FROM normalized_events WHERE superseded_by IS NULL "
                       "GROUP BY category_name")
        cat_rows = cursor.fetchall()
        events_by_category = {r["category_name"]: r["cnt"] for r in cat_rows}

        # 5. Events by source
        cursor.execute(
            """
            SELECT s.name, COUNT(n.id) as cnt
            FROM sources s
            LEFT JOIN raw_logs r ON s.id = r.source_id
            LEFT JOIN normalized_events n ON r.id = n.raw_id AND n.superseded_by IS NULL
            GROUP BY s.name
            """
        )
        src_rows = cursor.fetchall()
        events_by_source = {r["name"]: r["cnt"] for r in src_rows}

        # 6. Events by severity
        cursor.execute("SELECT severity, COUNT(*) as cnt FROM normalized_events WHERE superseded_by IS NULL GROUP BY severity")
        sev_rows = cursor.fetchall()
        events_by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        # 7. Recent events
        cursor.execute(
            """
            SELECT n.sequence_num, n.time, n.class_name, n.severity, n.src_ip, n.dst_ip, n.action, s.name as source_name
            FROM normalized_events n
            JOIN raw_logs r ON n.raw_id = r.id
            JOIN sources s ON r.source_id = s.id
            WHERE n.superseded_by IS NULL
            ORDER BY n.sequence_num DESC
            LIMIT 10
            """
        )
        recent_events = [dict(r) for r in cursor.fetchall()]

        # 8. Integrity check quick summary
        cursor.execute("SELECT COUNT(*) FROM integrity_ledger")
        ledger_count = cursor.fetchone()[0]

        # 9. Measured quality: how events were parsed, OCSF conformance of the latest events, counts adding up
        parsing = parse_breakdown(conn)
        conformance = ocsf_conformance(conn)
        counts = pipeline_counts(conn)
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(count), 0) FROM log_formats WHERE status = 'new'")
        new_formats, new_format_lines = cursor.fetchone()

    return {
        "total_events": total_events,
        "active_sources": active_sources,
        "total_parsers": total_parsers,
        "approved_parsers": approved_parsers,
        # share of current events read by a vendor pack or an approved learned parser (not a constant)
        "parser_success_rate": parsing["known_parser_pct"],
        # share of the latest events whose OCSF export passes the OCSF 1.1.0 checks
        "normalization_success_rate": conformance["valid_pct"],
        "parsing": parsing,
        "ocsf_conformance": conformance,
        "pipeline": counts,
        "new_formats": {"formats": new_formats, "lines": new_format_lines},
        "ledger_entries": ledger_count,
        "events_by_category": events_by_category,
        "events_by_source": events_by_source,
        "events_by_severity": events_by_severity,
        "recent_events": recent_events
    }


@router.get("/unparsed")
def unparsed_lines(limit: int = 5):
    """The latest stored lines no parser could classify (OCSF Base Events), with the parser that handled them."""
    limit = max(1, min(int(limit), 50))
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT n.sequence_num, n.time, r.raw_text, s.name AS source_name, "
            "COALESCE(json_extract(n.unmapped_json, '$.parser_pack'), r.format_detected) AS parser, "
            "json_extract(n.unmapped_json, '$.parse_error') AS parse_error "
            "FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id JOIN sources s ON s.id = r.source_id "
            "WHERE n.superseded_by IS NULL AND n.class_uid = 0 ORDER BY n.sequence_num DESC LIMIT ?",
            (limit,)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM normalized_events WHERE superseded_by IS NULL AND class_uid = 0"
                             ).fetchone()[0]
    return {"total": total, "lines": [dict(r) for r in rows]}
