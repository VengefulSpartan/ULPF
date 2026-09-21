import streamlit as st
import json
import pandas as pd
from frontend.api_client import APIClient

def render_sources():
    st.markdown("## Sources & Onboarding")
    st.caption("Manage perimeter network appliances, ingestion channels, and parser associations")

    tab_list, tab_add, tab_test = st.tabs(["Active Sources", "➕ Register New Source", "🧪 Test Ingestion & Normalization"])

    # 1. Active Sources Tab
    with tab_list:
        sources = APIClient.list_sources()
        if sources:
            df = pd.DataFrame(sources)
            cols = ["name", "vendor", "product", "format_type", "category", "event_count", "last_event_at"]
            st.dataframe(df[[c for c in cols if c in df.columns]], use_container_width=True, hide_index=True)
        else:
            st.warning("No log sources configured yet. Register a source or load demo datasets.")

        st.markdown("---")
        st.markdown("##### Ingestion Protocols & Channel Status")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">HTTP POST API</div>
                    <div class="metric-value" style="font-size:1.2rem; color:#2E7D32;">● Active</div>
                    <div class="metric-subtext">Endpoint: /api/ingest/*</div>
                </div>
                """, unsafe_allow_html=True
            )
        with c2:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">Batch File Upload</div>
                    <div class="metric-value" style="font-size:1.2rem; color:#2E7D32;">● Active</div>
                    <div class="metric-subtext">Supports .log, .txt, .json</div>
                </div>
                """, unsafe_allow_html=True
            )
        with c3:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">UDP/TCP Syslog 514</div>
                    <div class="metric-value" style="font-size:1.2rem; color:#6C63A8;">● Socket Daemon</div>
                    <div class="metric-subtext">Local demo listener module</div>
                </div>
                """, unsafe_allow_html=True
            )
        with c4:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">Cloud Pub/Sub (Kafka/AWS)</div>
                    <div class="metric-value" style="font-size:1.2rem; color:#94A3B8;">○ Enterprise Connector</div>
                    <div class="metric-subtext">Production enterprise tier</div>
                </div>
                """, unsafe_allow_html=True
            )

    # 2. Add Source Tab
    with tab_add:
        st.markdown("##### Register a Perimeter Network Source")
        with st.form("add_source_form"):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Source Identifier / Name", placeholder="e.g. PA-5200-Border-FW")
                vendor = st.selectbox("Device Vendor", ["Palo Alto Networks", "Cisco", "Fortinet", "Suricata", "Check Point", "pfSense", "Generic"])
                product = st.text_input("Product Model", placeholder="e.g. PAN-OS, ASA, FortiGate, Snort")
            with col2:
                format_type = st.selectbox("Log Format", ["cef", "syslog", "kv", "json", "leef", "auto"])
                category = st.selectbox("Appliance Category", ["firewall", "vpn", "ids", "router", "proxy", "network"])
                desc = st.text_area("Description / Network Location", placeholder="Border perimeter egress point")

            submitted = st.form_submit_button("Register Source", type="primary")
            if submitted:
                if not name or not product:
                    st.error("Name and Product Model are required.")
                else:
                    try:
                        res = APIClient.create_source({
                            "name": name,
                            "vendor": vendor,
                            "product": product,
                            "format_type": format_type,
                            "category": category,
                            "description": desc,
                            "is_active": True
                        })
                        st.success(f"Source '{res.get('name')}' created successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error creating source: {str(e)}")

    # 3. Test Ingestion Tab
    with tab_test:
        st.markdown("##### Instant Ingestion & Normalization Sandbox")
        sources = APIClient.list_sources()
        if not sources:
            st.info("Please register or load a source first.")
            return

        source_map = {f"{s['name']} ({s['vendor']} {s['product']})": s['id'] for s in sources}
        selected_source_label = st.selectbox("Select Target Source", list(source_map.keys()))
        selected_source_id = source_map[selected_source_label]
        sel_source = next(s for s in sources if s["id"] == selected_source_id)

        sample_text = st.text_area(
            "Paste Raw Log Line",
            value='CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.25 dst=192.168.1.100 spt=44123 dpt=80 proto=TCP act=allow',
            height=100
        )

        if st.button("⚡ Test Ingest & Normalize", type="primary"):
            try:
                res = APIClient.ingest_single(
                    text=sample_text,
                    source_id=selected_source_id,
                    vendor=sel_source["vendor"],
                    product=sel_source["product"]
                )
                st.success("✓ Log successfully pre-processed, normalized, and appended to hash ledger!")
                
                col_r1, col_r2 = st.columns(2)
                with col_r1:
                    st.markdown("**1. Lossless Raw Storage & Lineage:**")
                    st.markdown(f"**Sequence Number**: `#{res.get('sequence_num')}`")
                    st.markdown(f"**Detected Format**: `{res.get('format_detected')}`")
                    st.markdown(f"**Raw SHA-256 Hash**:")
                    st.code(res.get('raw_hash'), language="text")
                with col_r2:
                    st.markdown("**2. OCSF Normalization:**")
                    st.markdown(f"**OCSF Class**: `{res.get('ocsf_class')}`")
                    st.markdown(f"**Assigned Severity**: `{res.get('severity')}`")
                    st.markdown(f"**Event UUID**: `{res.get('event_id')}`")
            except Exception as e:
                st.error(f"Ingestion failed: {str(e)}")
