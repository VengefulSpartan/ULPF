import streamlit as st
import json
import pandas as pd
from frontend.api_client import APIClient

def render_explorer():
    st.markdown("## Log Explorer")
    st.caption("Investigate normalized OCSF security events with dual-pane raw payload traceability")

    # Filter Bar
    c_search, c_src, c_sev, c_cls = st.columns([2, 1, 1, 1])
    with c_search:
        search_query = st.text_input("Search Raw Logs / IPs", placeholder="e.g. 10.0.1.15, allow, exploit...")
    with c_src:
        sources = APIClient.list_sources()
        src_options = ["All Sources"] + [s["name"] for s in sources]
        selected_src_name = st.selectbox("Source Appliance", src_options)
        selected_src_id = next((s["id"] for s in sources if s["name"] == selected_src_name), None) if selected_src_name != "All Sources" else None
    with c_sev:
        selected_sev = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Informational"])
        sev_filter = None if selected_sev == "All" else selected_sev
    with c_cls:
        selected_cls = st.selectbox("OCSF Class", ["All", "Network Activity", "Authentication", "Security Finding"])
        cls_filter = None if selected_cls == "All" else selected_cls

    # Query Events
    res = APIClient.list_events(
        search=search_query if search_query else None,
        source_id=selected_source_id if selected_src_id else None,
        severity=sev_filter,
        class_name=cls_filter,
        limit=50
    )

    events = res.get("events", [])
    st.markdown(f"**Found {res.get('total', 0)} total events** (Showing top {len(events)})")

    if not events:
        st.info("No events match the specified query filters. Try resetting filters or loading sample datasets from the Overview page.")
        return

    # Table view
    table_data = []
    for e in events:
        table_data.append({
            "Seq": e.get("sequence_num"),
            "Time": e.get("time"),
            "Source": e.get("source_name"),
            "Class": e.get("class_name"),
            "Severity": e.get("severity"),
            "Src IP": f"{e.get('src_ip') or '-'}:{e.get('src_port') or ''}",
            "Dst IP": f"{e.get('dst_ip') or '-'}:{e.get('dst_port') or ''}",
            "Action": e.get("action") or "-",
            "Finding / Msg": e.get("finding_title") or e.get("user_name") or "-",
            "id": e.get("id")
        })

    df = pd.DataFrame(table_data)
    st.dataframe(
        df[["Seq", "Time", "Source", "Class", "Severity", "Src IP", "Dst IP", "Action", "Finding / Msg"]],
        use_container_width=True,
        hide_index=True
    )

    # Event Detail Inspection Panel
    st.markdown("---")
    st.markdown("##### Event Detail & Traceability Inspector")
    
    event_ids = [e["id"] for e in events]
    seq_labels = [f"Seq #{e['sequence_num']} — {e['class_name']} ({e['source_name']})" for e in events]
    selected_idx = st.selectbox("Select Event to Inspect", range(len(event_ids)), format_func=lambda i: seq_labels[i])
    
    sel_event = events[selected_idx]
    
    col_raw, col_norm = st.columns([1, 1])

    with col_raw:
        st.markdown("**1. Original Raw Event Payload (Lossless):**")
        st.markdown(f"<div class='raw-box'>{sel_event.get('raw_text')}</div>", unsafe_allow_html=True)
        st.markdown(f"**Format Detected**: `{sel_event.get('format_detected')}`")
        st.markdown(f"**Raw SHA-256 Hash**: <span class='hash-pill'>{sel_event.get('raw_hash')}</span>", unsafe_allow_html=True)

    with col_norm:
        st.markdown("**2. Normalized OCSF v1.1.0 Event:**")
        st.json(sel_event.get("normalized", {}))

    # Unmapped fields if any
    unmapped = sel_event.get("unmapped", {})
    if unmapped:
        with st.expander("Inspect Unmapped Source Fields"):
            st.json(unmapped)
