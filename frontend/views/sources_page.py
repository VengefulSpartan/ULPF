import pandas as pd
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient

VENDORS = ["Palo Alto Networks", "Cisco", "Fortinet", "Suricata", "Check Point", "pfSense", "Generic"]
SAMPLE_LINE = ("CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.25 dst=192.168.1.100 "
               "spt=44123 dpt=80 proto=TCP act=allow")


def _channels(conn: dict) -> str:
    by_type = {}
    for i in conn["inputs"]:
        t = i.get("type", "")
        key = "Syslog" if t.startswith("syslog") else "HTTP (HEC, OTLP, NDJSON)" if t == "http" else t.title()
        agg = by_type.setdefault(key, {"received": 0, "where": [], "last": None})
        agg["received"] += i.get("received", 0)
        agg["where"].append(i.get("listening") or i.get("name"))
        agg["last"] = max(filter(None, [agg["last"], i.get("last_received_at")]), default=None)
    if conn["http_receivers"]["enabled"]:
        by_type.setdefault("HTTP (HEC, OTLP, NDJSON)", {"received": 0, "where": ["/services/collector, /v1/logs"],
                                                        "last": None})
    cards = [ui.kpi(name, ui.num(agg["received"]) + " <small>received</small>",
                    f"<span>{ui.esc(' · '.join(str(w) for w in agg['where'][:3]))}</span>",
                    dot="good" if agg["received"] else "muted")
             for name, agg in by_type.items()]
    return f'<div class="tl-kpis" style="grid-template-columns:repeat({max(len(cards), 1)}, minmax(0, 1fr))">{"".join(cards)}</div>'


def render_sources():
    sources = APIClient.list_sources()
    events = sum(s.get("event_count") or 0 for s in sources)
    ui.page_header("Sources", f"<b>{len(sources)}</b> sources · {ui.num(events)} events")

    tab_list, tab_add, tab_test = st.tabs(["Sources", "Add a source", "Try a log line"])

    with tab_list:
        if sources:
            df = pd.DataFrame(sources)
            cols = {"name": "Name", "vendor": "Vendor", "product": "Product", "format_type": "Format",
                    "category": "Type", "event_count": "Events", "last_event_at": "Last event"}
            st.dataframe(df[[c for c in cols if c in df.columns]].rename(columns=cols), width="stretch",
                         hide_index=True)
        else:
            st.info("No sources yet. A device appears here with its first message, or add one by hand.")

        st.markdown('<div class="tl-subhead">Inputs</div>', unsafe_allow_html=True)
        conn = APIClient.get_connectors()
        if conn is None:
            st.info("The API is not running, so there are no network inputs. File upload and single lines still work.")
        else:
            st.markdown(_channels(conn), unsafe_allow_html=True)
            st.caption("A new device is added here on its first message. Setup for each vendor is on the Connectors page.")

    with tab_add:
        with st.form("add_source_form", border=False):
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Name", placeholder="PA-5200-border")
                vendor = st.selectbox("Vendor", VENDORS)
                product = st.text_input("Product", placeholder="PAN-OS, ASA, FortiGate, Snort")
            with col2:
                format_type = st.selectbox("Log format", ["cef", "syslog", "kv", "json", "leef", "auto"])
                category = st.selectbox("Device type", ["firewall", "vpn", "ids", "router", "proxy", "network"])
                desc = st.text_area("Notes", placeholder="Where it sits, what it protects", height=96)

            if st.form_submit_button("Add source", type="primary"):
                if not name or not product:
                    st.error("Name and product are required.")
                else:
                    try:
                        res = APIClient.create_source({"name": name, "vendor": vendor, "product": product,
                                                       "format_type": format_type, "category": category,
                                                       "description": desc, "is_active": True})
                        st.toast(f"Added {res.get('name')}.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Could not add the source: {e}")

    with tab_test:
        if not sources:
            st.info("Add a source or load the sample data first.")
            return
        source_map = {f"{s['name']} ({s['vendor']} {s['product']})": s["id"] for s in sources}
        label = st.selectbox("Source", list(source_map))
        sel_source = next(s for s in sources if s["id"] == source_map[label])
        sample_text = st.text_area("Log line", value=SAMPLE_LINE, height=90)
        st.caption("The line is archived, parsed and chained like any other event.")

        if st.button("Ingest this line", type="primary"):
            try:
                res = APIClient.ingest_single(text=sample_text, source_id=sel_source["id"],
                                              vendor=sel_source["vendor"], product=sel_source["product"])
            except Exception as e:
                st.error(f"Ingest failed: {e}")
                return
            st.success(f"Stored as event #{res.get('sequence_num')}.")
            col1, col2 = st.columns(2)
            with col1.container(key="tile-src-raw"):
                st.markdown("**Archived line**")
                st.markdown(f"Format detected: `{res.get('format_detected')}`")
                st.markdown("SHA-256 of the raw bytes:")
                st.code(res.get("raw_hash"), language="text")
            with col2.container(key="tile-src-ocsf"):
                st.markdown("**Normalized event**")
                st.markdown(f"OCSF class: `{res.get('ocsf_class')}`")
                st.markdown(f"Severity: `{res.get('severity')}`")
                st.markdown(f"Event ID: `{res.get('event_id')}`")
