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

    parsing = kpis.get("parsing") or {}
    conf = kpis.get("ocsf_conformance") or {}
    pipe = kpis.get("pipeline") or {}
    fresh = kpis.get("new_formats") or {}

    def card(col, title, value, sub, color="#123B5D"):
        col.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">{title}</div>
                <div class="metric-value" style="color:{color};">{value}</div>
                <div class="metric-subtext">{sub}</div>
            </div>""", unsafe_allow_html=True)

    # Top KPI Cards: every number is measured from the database
    m1, m2, m3, m4, m5 = st.columns(5)
    revisions = pipe.get("revisions", 0)
    card(m1, "Normalized events", f"{total_events:,}",
         f"current versions · {revisions:,} re-parsed" if revisions else "OCSF 1.1.0, one per archived line")
    card(m2, "Active sources", f"{active_sources:,}", "devices and forwarders")
    known = parsing.get("known_parser_pct", 0.0)
    card(m3, "Read by a known parser", f"{known}%" if total_events else "–",
         f"{parsing.get('vendor_pack', 0):,} vendor packs · {parsing.get('learned', 0):,} learned · "
         f"{parsing.get('generic', 0):,} generic (unverified)",
         "#2E7D32" if known >= 90 else "#B45309" if total_events else "#123B5D")
    valid = conf.get("valid_pct", 0.0)
    card(m4, "OCSF 1.1.0 conformance", f"{valid}%" if conf.get("checked") else "–",
         f"latest {conf.get('checked', 0):,} events checked against OCSF",
         "#2E7D32" if valid == 100 else "#B91C1C" if conf.get("checked") else "#123B5D")
    ok = pipe.get("consistent", True)
    card(m5, "Integrity chain", f"{ledger_count:,}",
         "one record per event" if ok else "counts do not add up: verify the chain", "#123B5D" if ok else "#B91C1C")

    if fresh.get("formats"):
        st.warning(f"**{fresh['lines']:,} lines from {fresh['formats']} log format(s) no parser knows** were archived "
                   "and parsed without guessing: only fields with evidence are filled, and they are marked unverified. "
                   "Review them in **Parser Studio > New log formats** to learn and approve a parser.")
    for problem, n in conf.get("top_failures") or []:
        st.error(f"OCSF check failed on {n} of the latest events: {problem}")

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
            labels = {"Uncategorized": "Base Event (not classified yet)"}
            df_cat = pd.DataFrame([(labels.get(k, k), v) for k, v in by_cat.items()], columns=["Category", "Count"])
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
