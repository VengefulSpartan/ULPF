import streamlit as st

from backend.config import settings
from frontend import ui

def _cards(cards) -> str:
    return f'<div class="tl-kpis" style="grid-template-columns:repeat({len(cards)}, minmax(0, 1fr))">{"".join(cards)}</div>'


def _reset() -> None:
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
    with st.popover("Delete all stored events"):
        st.markdown("This deletes every stored event, raw line, chain record and incident. Sources stay.")
        st.button("Delete everything", type="primary", on_click=_reset)
