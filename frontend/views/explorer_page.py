import pandas as pd
import streamlit as st

from frontend import ui, widgets
from frontend.api_client import APIClient

SEVERITIES = ["All", "Critical", "High", "Medium", "Low", "Informational"]
CLASSES = ["All", "Network Activity", "Authentication", "Detection Finding", "Base Event"]


def _address(ip, port) -> str:
    return f"{ip}:{port}" if ip and port else ip or "-"


def render_explorer():
    header = st.empty()
    c_search, c_src, c_sev, c_cls = st.columns([2, 1, 1, 1])
    search_query = c_search.text_input("Search", placeholder="An address, a user, any word in the raw line")
    sources = APIClient.list_sources()
    selected_src_name = c_src.selectbox("Source", ["All"] + [s["name"] for s in sources])
    selected_src_id = next((s["id"] for s in sources if s["name"] == selected_src_name), None)
    selected_sev = c_sev.selectbox("Severity", SEVERITIES)
    selected_cls = c_cls.selectbox("OCSF class", CLASSES)

    res = APIClient.list_events(
        search=search_query or None,
        source_id=selected_src_id,
        severity=None if selected_sev == "All" else selected_sev,
        class_name=None if selected_cls == "All" else selected_cls,
        limit=50,
    )
    events = res.get("events", [])
    with header.container():
        ui.page_header("Log Explorer", f"<b>{ui.num(res.get('total', 0))}</b> events match · newest "
                                       f"{len(events)} shown · select a row to see its raw line and OCSF event")
    if not events:
        st.info("No events match these filters.")
        return

    df = pd.DataFrame([{
        "#": e.get("sequence_num"),
        "Time (UTC)": (e.get("time") or "")[:19].replace("T", " "),
        "Source": e.get("source_name"),
        "Class": e.get("class_name"),
        "Severity": e.get("severity"),
        "From": _address(e.get("src_ip"), e.get("src_port")),
        "To": _address(e.get("dst_ip"), e.get("dst_port")),
        "Action": e.get("action") or "-",
        "Detail": e.get("finding_title") or e.get("user_name") or "-",
    } for e in events])
    picked = st.dataframe(df, width="stretch", hide_index=True, height=320, on_select="rerun",
                          selection_mode="single-row", key="explorer_rows")
    rows = picked.selection.rows if picked and picked.selection else []
    sel_event = events[rows[0]] if rows else events[0]

    col_raw, col_norm = st.columns(2, gap="medium")
    with col_raw.container(key="tile-ex-raw"):
        st.markdown(f'<div class="tl-tile__title">Raw line · event #{sel_event.get("sequence_num")}</div>',
                    unsafe_allow_html=True)
        st.code(sel_event.get("raw_text") or "", language="text", wrap_lines=True)
        st.markdown(f'<div class="tl-facts"><span>Format <b>{ui.esc(sel_event.get("format_detected"))}</b></span>'
                    f'<span>Source <b>{ui.esc(sel_event.get("source_name"))}</b></span></div>'
                    f'<div class="tl-hash" style="margin-top:6px">SHA-256 {ui.esc(sel_event.get("raw_hash"))}</div>',
                    unsafe_allow_html=True)
        seq = sel_event.get("sequence_num")
        widgets.evidence_bundle("ex-evidence", {
            f"Event #{seq}": {"sequences": [seq]},
            f"The {len(events)} shown": {"sequences": [e.get("sequence_num") for e in events]},
        })
        unmapped = sel_event.get("unmapped", {})
        if unmapped:
            with st.expander("Fields not mapped to OCSF"):
                st.json(unmapped)

    with col_norm.container(key="tile-ex-ocsf"):
        from backend.services.normalization.ocsf_export import to_ocsf, validate
        ocsf_event = to_ocsf(sel_event.get("normalized") or {})
        problems = validate(ocsf_event)
        verdict = ('<span class="tl-sevtag"><span class="tl-dot tl-dot--good"></span>passes the OCSF checks</span>'
                   if not problems else
                   f'<span class="tl-sevtag"><span class="tl-dot tl-dot--critical"></span>{ui.esc("; ".join(problems))}</span>')
        st.markdown(f'<div class="tl-tile__head"><span class="tl-tile__title">OCSF 1.1.0 event, as sent to the outputs'
                    f'</span><span class="tl-tile__aside">{verdict}</span></div>', unsafe_allow_html=True)
        st.json(ocsf_event, expanded=2)
        with st.expander("Stored record (what the chain covers)"):
            st.json(sel_event.get("normalized", {}))
