import streamlit as st
from backend.config import settings
from backend.services.storage.db import db

def render_settings():
    st.markdown("## System Settings & Environment")
    st.caption("Application runtime parameters, retention policies, and cryptographic security configuration")

    st.markdown("##### Environment & Runtime Mode")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Deployment Mode</div>
                <div class="metric-value" style="font-size:1.2rem; color:#123B5D;">{settings.ENVIRONMENT.upper()}</div>
                <div class="metric-subtext">Air-Gapped / Standalone</div>
            </div>
            """, unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Parser Generation Engine</div>
                <div class="metric-value" style="font-size:1.2rem; color:#0077B6;">Offline Heuristics</div>
                <div class="metric-subtext">Zero external API dependencies</div>
            </div>
            """, unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Cryptographic Hash</div>
                <div class="metric-value" style="font-size:1.2rem; color:#2E7D32;">SHA-256 Chain</div>
                <div class="metric-subtext">Sequential transaction ledger</div>
            </div>
            """, unsafe_allow_html=True
        )

    st.markdown("---")

    st.markdown("##### Storage & Database Parameters")
    st.markdown(
        f"""
        - **Storage Engine**: SQLite 3 with Write-Ahead Logging (`WAL` mode)
        - **Database Path**: `{settings.DB_PATH}`
        - **Schema Version**: `1.0.0`
        - **API Binding**: `{settings.BACKEND_HOST}:{settings.BACKEND_PORT}`
        - **Secrets Policy**: Zero API keys or sensitive credentials exposed in frontend
        """
    )

    st.markdown("##### Governance & Approval Policies")
    st.checkbox("Enforce Test Validation Before Parser Approval", value=True, disabled=True, help="Prevents untested candidate parsers from being promoted to active parsing.")
    st.checkbox("Maintain Lossless Raw Byte Ledger", value=True, disabled=True, help="Preserves exact original log payload string and calculates SHA-256 upon arrival.")
    st.checkbox("Enforce Transactional Sequential Monotonicity", value=True, disabled=True, help="Ensures sequence numbers have zero gaps and zero reordering.")

    st.markdown("---")
    st.markdown("##### Database Maintenance")
    if st.button("🧹 Reset Database & Flush Sample Data", type="secondary"):
        with db.get_connection() as conn:
            conn.execute("DELETE FROM integrity_ledger;")
            conn.execute("DELETE FROM normalized_events;")
            conn.execute("DELETE FROM raw_logs;")
            conn.execute("DELETE FROM incidents;")
            conn.execute("DELETE FROM audit_tamper_backup;")
            conn.execute("UPDATE sources SET event_count = 0, last_event_at = NULL;")
            conn.commit()
        st.success("Database tables flushed. Navigate to Overview to re-seed sample data.")
        st.rerun()
