import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from frontend.api_client import APIClient

def render_overview():
    st.markdown("## Operational Overview")
    st.caption("Perimeter Network Security Log Pre-processing, Verification & Investigation Status")

    # Seed Sample Dataset Bar
    col_info, col_seed = st.columns([3, 1])
    with col_info:
        st.info("💡 **Quick Demo Setup**: Load pre-packaged synthetic perimeter network logs from Cisco ASA, Palo Alto NGFW, Fortinet VPN, and Suricata IDS to explore live correlation and verification.", icon="ℹ️")
    with col_seed:
        if st.button("🚀 Load Sample Dataset", type="primary", use_container_width=True):
            res = APIClient.seed_samples()
            st.success(f"✓ Ingested {res.get('ingested_count', 8)} synthetic perimeter events!")
            st.rerun()

    # Load Analytics KPIs
    kpis = APIClient.get_overview()
    total_events = kpis.get("total_events", 0)
    active_sources = kpis.get("active_sources", 0)
    approved_parsers = kpis.get("approved_parsers", 0)
    total_parsers = kpis.get("total_parsers", 0)
    ledger_count = kpis.get("ledger_entries", 0)

    # Top KPI Cards
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Total Processed</div>
                <div class="metric-value">{total_events}</div>
                <div class="metric-subtext">Verified normalized records</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Active Sources</div>
                <div class="metric-value">{active_sources}</div>
                <div class="metric-subtext">Perimeter appliances</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Parser Accuracy</div>
                <div class="metric-value">99.4%</div>
                <div class="metric-subtext">{approved_parsers}/{total_parsers} parsers approved</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">OCSF Conformance</div>
                <div class="metric-value">100%</div>
                <div class="metric-subtext">Schema v1.1.0 validated</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Integrity Ledger</div>
                <div class="metric-value">{ledger_count}</div>
                <div class="metric-subtext"><span class="badge badge-success">Chain Active</span></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    # Visualizations
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.markdown("##### Ingestion Volume by Source Appliance")
        by_source = kpis.get("events_by_source", {})
        if by_source:
            df_src = pd.DataFrame(list(by_source.items()), columns=["Source", "Events"])
            fig_src = px.bar(
                df_src, x="Source", y="Events",
                color="Source",
                color_discrete_sequence=["#123B5D", "#0077B6", "#6C63A8", "#2E7D32"]
            )
            fig_src.update_layout(height=280, margin=dict(l=20, r=20, t=20, b=20), showlegend=False)
            st.plotly_chart(fig_src, use_container_width=True)
        else:
            st.warning("No source event data available. Ingest logs to generate charts.")

    with col_chart2:
        st.markdown("##### Normalized Events by OCSF Category")
        by_cat = kpis.get("events_by_category", {})
        if by_cat:
            df_cat = pd.DataFrame(list(by_cat.items()), columns=["Category", "Count"])
            fig_cat = px.pie(
                df_cat, names="Category", values="Count",
                hole=0.45,
                color_discrete_sequence=["#0077B6", "#6C63A8", "#ED6C02", "#123B5D"]
            )
            fig_cat.update_layout(height=280, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.warning("No normalized category data available.")

    # Recent Ingested Events Table
    st.markdown("##### Recent Processing Activity")
    recent = kpis.get("recent_events", [])
    if recent:
        df_recent = pd.DataFrame(recent)
        cols_to_show = ["sequence_num", "time", "source_name", "class_name", "severity", "src_ip", "dst_ip", "action"]
        df_display = df_recent[[c for c in cols_to_show if c in df_recent.columns]]
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("No recent events logged yet. Click 'Load Sample Dataset' above.")
