import streamlit as st

from backend.config import settings
from frontend import ui
from frontend.api_client import APIClient

def _cards(cards) -> str:
    return f'<div class="tl-kpis" style="grid-template-columns:repeat({len(cards)}, minmax(0, 1fr))">{"".join(cards)}</div>'


def _reset() -> None:
    if settings.CERTIN_MODE:   # the button is disabled too; this is the rule, not only the button
        st.toast("CERT-In mode is on: stored events are kept for at least 180 days and cannot be deleted here.")
        return
    from backend.services.integrity import checkpoints
    from backend.services.storage.db import db
    with db.get_connection() as conn:
        conn.execute("DELETE FROM integrity_ledger;")
        conn.execute("DELETE FROM normalized_events;")
        try:
            conn.execute("INSERT INTO raw_search(raw_search) VALUES('delete-all');")
        except Exception:
            pass
        conn.execute("DROP TRIGGER IF EXISTS raw_logs_fts_delete;")
        conn.execute("DELETE FROM raw_logs;")
        conn.execute("DELETE FROM incidents;")
        conn.execute("DELETE FROM audit_tamper_backup;")
        conn.execute("UPDATE sources SET event_count = 0, last_event_at = NULL;")
        checkpoints.reset_log(conn)   # a new log for the witnesses; they keep what they signed for this one
        if getattr(settings, "SEARCH_INDEX", True):
            conn.execute("""CREATE TRIGGER IF NOT EXISTS raw_logs_fts_delete AFTER DELETE ON raw_logs BEGIN
                INSERT INTO raw_search (raw_search, rowid, raw_text) VALUES ('delete', old.rowid, old.raw_text);
            END;""")
        conn.commit()
        try:
            conn.execute("VACUUM;")
        except Exception:
            pass
    st.cache_data.clear()
    st.toast("All stored events deleted. Load the sample data on Overview to start again.")


def render_settings():
    ui.page_header("Settings", "How this installation is set up. Values come from environment variables and "
                               "config/tracelog.yaml; this page does not change them.")
    st.markdown(_cards([
        ui.kpi("Environment", ui.esc(settings.ENVIRONMENT), "<span>runs without internet access</span>"),
        ui.kpi("Parser learning", "On this machine", "<span>no external service, no LLM</span>"),
        ui.kpi("Integrity", "SHA-256 chain", "<span>one record per event, in sequence</span>"),
    ]), unsafe_allow_html=True)

    db_path = settings.DB_PATH if settings.DASHBOARD_DIRECT_MODE else "on the collector service (volume tracelog-data)"
    st.markdown('<div class="tl-subhead">Storage</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
        - **Database**: SQLite 3 in write-ahead-log (WAL) mode
        - **Path**: `{db_path}`
        - **API address**: `{settings.BACKEND_HOST}:{settings.BACKEND_PORT}`
        - **Secrets**: read from environment variables only; none reach the browser
        """
    )
    st.markdown('<div class="tl-subhead">Signed checkpoints</div>', unsafe_allow_html=True)
    witnesses = [u.strip() for u in settings.WITNESS_URLS.split(",") if u.strip()]
    st.markdown(
        f"""
        - **Sealed**: every {settings.CHECKPOINT_SIZE:,} records, and every {settings.CHECKPOINT_EVERY_SECONDS} s whatever is left
        - **Signed with**: Ed25519, plus ML-DSA-65 (FIPS 204) where the installed `cryptography` supports it
        - **Witnesses**: {", ".join(f"`{w}`" for w in witnesses) if witnesses else "none configured (WITNESS_URLS)"}
        - **Keys**: `{settings.TRACELOG_KEY_DIR or "keys/ next to the database"}`, readable by the service's user only, never committed
        """
    )

    st.markdown('<div class="tl-subhead">CERT-In mode</div>', unsafe_allow_html=True)
    status = APIClient.certin_status()
    if "error" in status:
        st.caption(f"Status not available: {status['error']}")
    else:
        days, keep = status.get("days_held", 0), status.get("retention_days", 180)
        st.markdown(_cards([
            ui.kpi("CERT-In mode", "On" if status.get("certin_mode") else "Off",
                   "<span>set CERTIN_MODE=true to turn it on</span>" if not status.get("certin_mode") else
                   "<span>stored events cannot be deleted here</span>", dot="good" if status.get("certin_mode") else None),
            ui.kpi("Logs held", f"{days:g} <small>of {keep} days</small>",
                   f"<span>since {ui.esc(status.get('oldest_received_ist') or '-')}</span>", extra=ui.meter(100 * min(days / keep, 1))),
            ui.kpi("Successful / failed events", f"{ui.num(status.get('successful_events', 0))} / "
                                                 f"{ui.num(status.get('failed_or_blocked_events', 0))}",
                   "<span>both are kept, as the directions ask</span>"),
            ui.kpi("Kept in", ui.esc(status.get("data_location") or "Not declared"),
                   "<span>DATA_LOCATION, as the operator declares it</span>",
                   dot=None if status.get("data_location") else "warning"),
        ]), unsafe_allow_html=True)
        st.caption(f"Incidents go to {status.get('report_to')} within {status.get('report_within_hours', 6):g} hours of "
                   f"being noticed: Correlation, then CERT-In report draft. Clocks: sync to "
                   f"{', '.join(status.get('clock_sources') or [])}.")

    st.markdown('<div class="tl-subhead">Rules that always apply</div>', unsafe_allow_html=True)
    st.markdown(
        """
        - A parser has to pass its test before it can be approved.
        - Every raw line is kept byte for byte, with its SHA-256.
        - Sequence numbers have no gaps and never go backwards.
        """
    )

    st.markdown('<div class="tl-subhead">Database</div>', unsafe_allow_html=True)
    if not settings.DASHBOARD_DIRECT_MODE:
        # the containers: the dashboard has no database, and only the collector writes to it
        st.button("Delete all stored events", disabled=True)
        st.caption("The database belongs to the collector service. To start from an empty archive: "
                   "`docker compose down -v`, then `docker compose up -d`.")
        return
    if settings.CERTIN_MODE:
        st.button("Delete all stored events", disabled=True)
        st.caption("CERT-In mode is on: logs are kept for at least 180 days.")
        return
    with st.popover("Delete all stored events"):
        st.markdown("This deletes every stored event, raw line, chain record, checkpoint and incident. Sources "
                    "stay. The witnesses keep what they signed; the archive starts a new log.")
        st.button("Delete everything", type="primary", on_click=_reset)
