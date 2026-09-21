import streamlit as st
import json
from frontend.api_client import APIClient
from backend.config import settings

def render_integrations():
    st.markdown("## Integrations & Export")
    st.caption("Downstream security tooling export, SIEM forwarding configurations, and REST endpoints")

    st.markdown(
        """
        > **Integration Transparency**: Downstream SIEM connectors are documented integration templates. 
        > ULPF produces canonical, analytics-ready OCSF events ready for immediate consumption by modern SIEMs.
        """
    )

    tab_export, tab_siem, tab_api = st.tabs(["💾 Data Export", "🔌 SIEM Forwarder Configurations", "📡 REST API Specifications"])

    with tab_export:
        st.markdown("##### Download Processed Telemetry")
        st.write("Export pre-processed, OCSF-normalized events with full hash-chain integrity metadata.")

        c_exp1, c_exp2 = st.columns(2)
        with c_exp1:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">Canonical OCSF JSON</div>
                    <div style="margin: 8px 0; font-size:0.88rem; color:#475569;">
                        Standardized JSON document array conforming to OCSF v1.1.0 specification.
                    </div>
                </div>
                """, unsafe_allow_html=True
            )
            # Fetch JSON
            events_data = APIClient.list_events(limit=500).get("events", [])
            norm_only = [e.get("normalized") for e in events_data if e.get("normalized")]
            json_str = json.dumps(norm_only, indent=2)
            st.download_button(
                "📥 Download OCSF JSON (.json)",
                data=json_str,
                file_name="ulpf_normalized_ocsf.json",
                mime="application/json",
                use_container_width=True
            )

        with c_exp2:
            st.markdown(
                """
                <div class="metric-card">
                    <div class="metric-title">Tabular CSV Format</div>
                    <div style="margin: 8px 0; font-size:0.88rem; color:#475569;">
                        Flattened CSV table with sequence numbers, endpoints, actions, and raw hashes.
                    </div>
                </div>
                """, unsafe_allow_html=True
            )
            import io
            import csv
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["sequence_num", "time", "class_name", "severity", "src_ip", "dst_ip", "action", "raw_hash"])
            writer.writeheader()
            for e in events_data:
                writer.writerow({
                    "sequence_num": e.get("sequence_num"),
                    "time": e.get("time"),
                    "class_name": e.get("class_name"),
                    "severity": e.get("severity"),
                    "src_ip": e.get("src_ip"),
                    "dst_ip": e.get("dst_ip"),
                    "action": e.get("action"),
                    "raw_hash": e.get("raw_hash")
                })
            csv_str = output.getvalue()
            st.download_button(
                "📥 Download CSV Table (.csv)",
                data=csv_str,
                file_name="ulpf_normalized_events.csv",
                mime="text/csv",
                use_container_width=True
            )

    with tab_siem:
        st.markdown("##### Downstream SIEM Connector Profiles")
        with st.expander("Splunk HTTP Event Collector (HEC)"):
            st.markdown("Status: **Configured Template (Unconnected Placeholder)**")
            st.code(
                """# Splunk inputs.conf
[http://ulpf_ocsf_stream]
disabled = 0
index = perimeter_security
sourcetype = _json
token = <SPLUNK_HEC_TOKEN>
""", language="ini"
            )

        with st.expander("Elastic Security / Fleet Elasticsearch"):
            st.markdown("Status: **Configured Template (Unconnected Placeholder)**")
            st.code(
                """# Elastic Logstash Pipeline
input {
  http {
    port => 8088
    codec => json
  }
}
output {
  elasticsearch {
    hosts => ["https://elasticsearch.corp.local:9200"]
    index => "logs-ocsf.network-%{+YYYY.MM.dd}"
  }
}
""", language="ruby"
            )

    with tab_api:
        st.markdown("##### Interactive REST API Endpoints")
        st.markdown(
            f"""
            FastAPI OpenAPI interactive documentation is live at:
            - **Swagger UI**: [http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/docs](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/docs)
            - **ReDoc**: [http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/redoc](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/redoc)
            - **Health**: [http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/health](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/health)
            """
        )
