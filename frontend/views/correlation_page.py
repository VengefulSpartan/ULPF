import streamlit as st
import json
import plotly.express as px
import pandas as pd
from frontend.api_client import APIClient

def render_correlation():
    st.markdown("## Correlation & Root Cause Analysis (RCA)")
    st.caption("Events from different devices that share an address close together in time. Observed facts are "
               "stored events; relationships are rules that matched, shown with the evidence that made them match. "
               "There are no confidence scores: nothing here measures one.")

    col_filter, col_run = st.columns([3, 1])
    with col_filter:
        pivot_ip = st.text_input("Pivot Entity / IP Address (Optional)", value="10.0.1.15")
    with col_run:
        st.write("")
        st.write("")
        run_btn = st.button("⚡ Run RCA Correlation", type="primary", use_container_width=True)

    incident = APIClient.run_correlation(pivot_ip=pivot_ip if pivot_ip else None)

    if not incident or not incident.get("observed_facts"):
        st.info("No correlated multi-device sequence found. Load sample datasets from the Overview page.")
        return

    # Incident Overview Header
    sev = incident.get("severity", "Unknown")
    badge_color = "error" if sev in ["High", "Critical", "Fatal"] else "warning"
    links = incident.get("inferred_relationships", [])

    st.markdown(
        f"""
        <div style="background-color: #F4F7FA; border: 1px solid #DCE3EA; border-left: 5px solid #0077B6; border-radius: 6px; padding: 18px; margin: 15px 0;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; color:#123B5D;">{incident.get('title')}</h3>
                <span class="badge badge-{badge_color}" style="font-size:0.9rem;" title="Highest severity any device reported">{sev.upper()} SEVERITY</span>
            </div>
            <div style="margin-top: 8px; color: #475569;">
                <b>Time Window</b>: {incident.get('start_time')} → {incident.get('end_time')} &nbsp;|&nbsp;
                <b>Events</b>: {len(incident.get('observed_facts', []))} &nbsp;|&nbsp;
                <b>Devices</b>: {len(incident.get('entities', {}).get('devices', []))} &nbsp;|&nbsp;
                <b>Rules matched</b>: {len(links)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Entities summary
    ent = incident.get("entities", {})
    e1, e2, e3 = st.columns(3)
    with e1:
        st.markdown(f"**Associated IPs**: `{', '.join(ent.get('ips', []))}`")
    with e2:
        st.markdown(f"**Identified Users**: `{', '.join(ent.get('users', [])) or 'None'}`")
    with e3:
        st.markdown(f"**Participating Devices**: `{', '.join(ent.get('devices', []))}`")

    st.markdown("---")

    # Chronological Plotly Timeline
    st.markdown("##### Chronological Multi-Device Investigation Timeline")
    facts = incident.get("observed_facts", [])
    if facts:
        timeline_rows = []
        for f in facts:
            timeline_rows.append({
                "Appliance": f"{f.get('source_vendor')} ({f.get('source_product')})",
                "Timestamp": f.get("timestamp"),
                "Event": f.get("event_class"),
                "Details": f.get("fact_description"),
                "Severity": f.get("severity")
            })
        df_timeline = pd.DataFrame(timeline_rows)
        
        fig = px.scatter(
            df_timeline,
            x="Timestamp",
            y="Appliance",
            color="Severity",
            hover_data=["Event", "Details"],
            color_discrete_map={
                "Critical": "#D32F2F",
                "High": "#ED6C02",
                "Medium": "#0077B6",
                "Low": "#6C63A8",
                "Informational": "#2E7D32"
            }
        )
        fig.update_traces(marker=dict(size=14, symbol="diamond"))
        fig.update_layout(height=260, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig, use_container_width=True)

    # Evidence Separation: Observed Facts vs Inferred Relationships
    col_facts, col_inferred = st.columns([1, 1])

    with col_facts:
        st.markdown("##### 🔍 Observed Facts (Verifiable Evidence)")
        st.caption("Hard telemetric facts logged directly by appliances, anchored with raw SHA-256 hashes:")
        for idx, f in enumerate(facts):
            st.markdown(
                f"""
                <div style="background-color: #FFFFFF; border: 1px solid #DCE3EA; border-radius: 4px; padding: 12px; margin-bottom: 10px;">
                    <div style="display:flex; justify-content:space-between;">
                        <b>#{f.get('sequence_num')} [{f.get('source_vendor')}] {f.get('event_class')}</b>
                        <span class="badge badge-info">{f.get('severity')}</span>
                    </div>
                    <div style="font-size:0.82rem; color:#334155; margin-top:4px;">{f.get('fact_description')}</div>
                    <div style="font-size:0.75rem; color:#64748B; margin-top:4px;">
                        Raw Hash: <code style="font-size:0.7rem;">{f.get('raw_hash')[:24]}...</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    with col_inferred:
        st.markdown("##### 🧠 Inferred Relationships (Rules that matched)")
        st.caption("Each rule is listed with the evidence that made it match. A match is not confirmed causation, "
                   "and it carries no probability.")
        inferred = links
        if inferred:
            for inf in inferred:
                evidence = "".join(f"<li>{e}</li>" for e in inf.get("evidence", []))
                st.markdown(
                    f"""
                    <div style="background-color: #F8FAFC; border: 1px dashed #0077B6; border-radius: 4px; padding: 12px; margin-bottom: 10px;">
                        <div style="display:flex; justify-content:space-between;">
                            <b>{inf.get('relationship_type')}</b>
                            <span class="badge badge-purple">{len(inf.get('source_event_ids', []))} events</span>
                        </div>
                        <ul style="font-size:0.8rem; color:#334155; margin:6px 0 0 0; padding-left:18px;">{evidence}</ul>
                        <div style="font-size:0.85rem; color:#0F172A; margin-top:4px;">
                            💡 <b>Hypothesis</b>: {inf.get('hypothesis')}
                        </div>
                        <div style="font-size:0.78rem; color:#475569; margin-top:4px;">
                            <b>Analytical Rationale</b>: {inf.get('rationale')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("No rule matched these events.")

    # Actionable Recommendations
    st.markdown("##### Triage & Remediation Recommendations")
    recs = incident.get("recommendations", [])
    for r in recs:
        st.markdown(f"- {r}")
