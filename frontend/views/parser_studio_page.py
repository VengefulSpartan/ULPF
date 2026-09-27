import pandas as pd
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient
from frontend.views.new_formats_panel import render_new_formats

DEFAULT_SAMPLES = (
    "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=allow\n"
    "CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|vulnerability|5|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=drop threat_name=\"SMB Remote Code Execution\"\n"
    "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|end|2|src=192.168.1.10 dst=8.8.8.8 spt=53000 dpt=53 proto=UDP act=allow bytes_sent=64 bytes_received=128"
)
STATUS_DOT = {"approved": "good", "rejected": "critical", "candidate": "warning"}


def _status(status: str) -> str:
    return (f'<span class="tl-sevtag"><span class="tl-dot tl-dot--{STATUS_DOT.get(status, "muted")}"></span>'
            f'{ui.esc(status)}</span>')


def render_parser_studio():
    parsers = APIClient.list_parsers()
    approved = sum(1 for p in parsers if p.get("status") == "approved")
    ui.page_header("Parser Studio", f"<b>{len(parsers)}</b> parsers · {approved} approved")

    tab_new, tab_gen, tab_list = st.tabs(["New log formats", "From samples", "Parsers"])

    with tab_new:
        render_new_formats()

    with tab_gen:
        _from_samples()

    with tab_list:
        if not parsers:
            st.info("No parsers yet. Propose one from samples, or learn one from a new log format.")
        for p in parsers:
            with st.expander(f"{p.get('name')} · {p.get('vendor')} {p.get('product')} · {p.get('status')}"):
                st.markdown(
                    f'<div class="tl-facts"><span>Status {_status(p.get("status", ""))}</span>'
                    f'<span>Format <b>{ui.esc(p.get("format_type"))}</b></span>'
                    f'<span>OCSF class <b>{ui.esc(p.get("target_ocsf_class"))}</b></span>'
                    f'<span>Approved by <b>{ui.esc(p.get("approved_by") or "nobody yet")}</b>'
                    f'{" on " + ui.esc(p.get("approved_at")) if p.get("approved_at") else ""}</span></div>',
                    unsafe_allow_html=True)
                if p.get("description"):
                    st.caption(p["description"])
                st.json(p.get("rule", {}), expanded=False)


def _from_samples():
    c1, c2, c3 = st.columns(3)
    p_name = c1.text_input("Parser name", value="PAN-OS traffic and threat")
    p_vendor = c2.text_input("Vendor", value="Palo Alto Networks")
    p_product = c3.text_input("Product", value="PA-5200")
    sample_text = st.text_area("Sample lines, one per line", value=DEFAULT_SAMPLES, height=120)
    lines = [l.strip() for l in sample_text.splitlines() if l.strip()]

    if st.button("Propose a parser", type="primary"):
        if not lines:
            st.error("Paste at least one sample line.")
        else:
            with st.spinner("Reading the samples…"):
                st.session_state["active_candidate"] = APIClient.generate_parser(
                    name=p_name, vendor=p_vendor, product=p_product, sample_logs=lines)

    active = st.session_state.get("active_candidate")
    if not active:
        return

    st.markdown('<div class="tl-subhead">Proposed mapping</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="tl-facts"><span>ID <b class="tl-mono">{ui.esc(active.get("id"))}</b></span>'
        f'<span>Format <b>{ui.esc(active.get("format_type"))}</b></span>'
        f'<span>Status {_status(active.get("status", ""))}</span>'
        f'<span>{"Tested" if active.get("tested") else "Not tested yet"}</span>'
        f'<span>OCSF class <b>{ui.esc(active.get("target_ocsf_class"))}</b> Network Activity</span></div>',
        unsafe_allow_html=True)
    mappings = (active.get("rule") or {}).get("mappings", [])
    if mappings:
        st.dataframe(pd.DataFrame(mappings), width="stretch", hide_index=True)

    st.markdown('<div class="tl-subhead">Test</div>', unsafe_allow_html=True)
    st.caption("A parser has to pass its test before it can be approved.")
    if st.button("Run the test"):
        with st.spinner("Parsing each sample…"):
            st.session_state["active_candidate"] = APIClient.test_parser(active.get("id"), lines)
            st.rerun()

    val = active.get("validation")
    if val:
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Lines tested", val.get("total_samples", 0))
        r2.metric("Passed", val.get("passed_samples", 0))
        r3.metric("Failed", val.get("failed_samples", 0))
        r4.metric("Accuracy", f"{val.get('accuracy_score', 0)}%")
        if val.get("unmapped_fields"):
            st.warning(f"Fields not mapped: {', '.join(val['unmapped_fields'])}")
        with st.expander("Results per line"):
            for idx, sample_res in enumerate(val.get("sample_results", [])):
                st.markdown(f"**Line {idx + 1}**: {'passed' if sample_res.get('passed') else 'failed'}")
                st.code(sample_res.get("sample_log"), language="text")
                if sample_res.get("extracted_fields"):
                    st.json(sample_res.get("extracted_fields"))

    st.markdown('<div class="tl-subhead">Decision</div>', unsafe_allow_html=True)
    col_app, col_rej, _ = st.columns([1, 1, 3])
    if col_app.button("Approve", type="primary", width="stretch"):
        res_app = APIClient.approve_parser(active.get("id"))
        if "error" in res_app:
            st.error(f"Approval refused: {res_app['error']}")
        else:
            st.session_state["active_candidate"] = res_app
            st.toast("Approved. New lines in this format are parsed with it.")
            st.rerun()
    if col_rej.button("Reject", width="stretch"):
        st.session_state["active_candidate"] = APIClient.reject_parser(active.get("id"))
        st.toast("Rejected.")
        st.rerun()
