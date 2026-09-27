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


DENIED = ("denied", "dropped", "blocked")
BUCKET_STEPS_S = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800)


def _bucket_ms(span_ms: int, target: int) -> int:
    """The smallest round slot (1 min, 2 min, 5 min … 1 week) that cuts the span into at most `target` slots."""
    for step in BUCKET_STEPS_S:
        if span_ms / (step * 1000) <= target:
            return step * 1000
    return BUCKET_STEPS_S[-1] * 1000


@router.get("/activity")
def activity(hours: float = 24, buckets: int = 48, findings: int = 60):
    """What happened in the newest `hours` of stored events (0: all of them), for the overview dashboard.

    The window ends at the newest event, not at the clock, so a day imported or replayed from the past
    still shows. Counts are of current events (re-parsed ones once). One query per breakdown, each on
    the time index.
    """
    buckets = max(6, min(int(buckets), 120))
    findings = max(0, min(int(findings), 200))
    with db.get_connection() as conn:
        newest, oldest, total = conn.execute(
            "SELECT MAX(time_epoch_ms), MIN(time_epoch_ms), COUNT(*) FROM normalized_events "
            "WHERE superseded_by IS NULL").fetchone()
        if not total:
            return {"events": 0, "window": None, "timeline": [], "findings": [], "by_source": [], "by_class": [],
                    "by_severity": [], "top_denied": [], "findings_by_severity": [],
                    "totals": {"events": 0, "denied": 0, "findings": 0, "sources": 0}}
        start = oldest if hours <= 0 else max(oldest, newest - int(hours * 3_600_000))
        step = _bucket_ms(max(newest - start, 60_000), buckets)
        start = start - start % step
        n = (newest - start) // step + 1
        where = "n.superseded_by IS NULL AND n.time_epoch_ms >= ? AND n.time_epoch_ms <= ?"
        args = (start, newest)
        marks = ",".join("?" * len(DENIED))

        rows = conn.execute(
            f"SELECT (n.time_epoch_ms - ?) / ? AS i, COUNT(*), SUM(n.disposition IN ({marks})) "
            f"FROM normalized_events n WHERE {where} GROUP BY i", (start, step, *DENIED, *args)).fetchall()
        by_slot = {int(i): (c, d or 0) for i, c, d in rows}
        timeline = [{"t": start + i * step, "events": by_slot.get(i, (0, 0))[0], "denied": by_slot.get(i, (0, 0))[1]}
                    for i in range(n)]

        found = conn.execute(
            f"SELECT n.sequence_num, n.time_epoch_ms, n.severity_id, n.severity, n.finding_title, n.src_ip, "
            f"n.user_name, s.name FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id "
            f"JOIN sources s ON s.id = r.source_id WHERE {where} AND n.class_uid = 2004 "
            f"ORDER BY n.time_epoch_ms DESC LIMIT ?", (*args, findings)).fetchall()
        finding_severity = conn.execute(
            f"SELECT n.severity_id, n.severity, COUNT(*) FROM normalized_events n WHERE {where} AND n.class_uid = 2004 "
            f"GROUP BY n.severity_id, n.severity ORDER BY n.severity_id DESC", args).fetchall()

        by_source = conn.execute(
            f"SELECT s.name, COUNT(*) FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id "
            f"JOIN sources s ON s.id = r.source_id WHERE {where} GROUP BY s.name ORDER BY 2 DESC", args).fetchall()
        by_class = conn.execute(
            f"SELECT n.class_name, COUNT(*) FROM normalized_events n WHERE {where} GROUP BY n.class_name "
            f"ORDER BY 2 DESC", args).fetchall()
        by_severity = conn.execute(
            f"SELECT n.severity_id, n.severity, COUNT(*) FROM normalized_events n WHERE {where} "
            f"GROUP BY n.severity_id, n.severity ORDER BY n.severity_id DESC", args).fetchall()
        top_denied = conn.execute(
            f"SELECT n.src_ip, COUNT(*) FROM normalized_events n WHERE {where} AND n.disposition IN ({marks}) "
            f"AND n.src_ip IS NOT NULL GROUP BY n.src_ip ORDER BY 2 DESC LIMIT 8", (*args, *DENIED)).fetchall()

    return {
        "events": total,
        "window": {"from_ms": start, "to_ms": newest, "bucket_ms": step, "hours": hours,
                   "oldest_ms": oldest},
        "timeline": timeline,
        "findings": [{"sequence_num": r[0], "time_ms": r[1], "severity_id": r[2], "severity": r[3], "title": r[4],
                      "src_ip": r[5], "user": r[6], "source": r[7]} for r in found],
        "by_source": [{"name": r[0], "events": r[1]} for r in by_source],
        "by_class": [{"name": r[0], "events": r[1]} for r in by_class],
        "by_severity": [{"id": r[0], "name": r[1], "events": r[2]} for r in by_severity],
        "top_denied": [{"src_ip": r[0], "events": r[1]} for r in top_denied],
        "findings_by_severity": [{"id": r[0], "name": r[1], "events": r[2]} for r in finding_severity],
        "totals": {"events": sum(t["events"] for t in timeline), "denied": sum(t["denied"] for t in timeline),
                   "findings": sum(r[2] for r in finding_severity), "sources": len(by_source)},
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
