from datetime import datetime

import streamlit as st

from frontend import ui
from frontend.api_client import APIClient

SEVERITY_ID = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5, "Fatal": 6}
RULES = {"LOGIN_THEN_ACTIVITY": "Login, then activity on another device",
         "ALLOWED_THEN_ALERT": "Connection allowed, then an alert on it",
         "PORT_SWEEP": "Many ports tried in a short time"}


def _ms(iso: str) -> int:
    try:
        return int(datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def _when(iso: str, fmt: str) -> str:
    ms = _ms(iso)
    return ui.utc(ms, fmt) if ms else ui.esc(iso)


def _run(pivot: str) -> None:
    st.session_state["rca_result"] = APIClient.run_correlation(pivot_ip=pivot or None)


def render_correlation():
    ui.page_header("Correlation", "Events from different devices that share an address, close together in time. "
                                  "Facts are stored events; links are rules that matched, each with its evidence. "
                                  "Nothing here is a confidence score.")
    col_filter, col_run = st.columns([3, 1], vertical_alignment="bottom")
    pivot_ip = col_filter.text_input("Address to start from", value="10.0.1.15",
                                     help="Leave empty to correlate the newest events from all devices.")
    col_run.button("Correlate", type="primary", width="stretch", on_click=_run, args=(pivot_ip,))

    incident = st.session_state.get("rca_result")
    if incident is None:
        st.info("Enter an address and select Correlate.")
        return
    facts = incident.get("observed_facts") or []
    if not facts:
        st.info("No events from more than one device share that address. Load the sample data, or try another address.")
        return

    links = incident.get("inferred_relationships") or []
    ent = incident.get("entities") or {}
    sev = incident.get("severity", "Unknown")
    st.markdown(
        f'<div class="tl-tile tl-span-12" style="margin-bottom:2px"><div class="tl-tile__head">'
        f'<span class="tl-tile__title" style="font-size:.95rem">{ui.esc(incident.get("title"))}</span>'
        f'<span class="tl-tile__aside">Highest severity reported {ui.sev_tag(SEVERITY_ID.get(sev, 2), sev)}</span></div>'
        f'<div class="tl-facts"><span>{_when(incident.get("start_time"), "%d %b %H:%M:%S")} to '
        f'{_when(incident.get("end_time"), "%H:%M:%S")} UTC</span>'
        f'<span><b>{len(facts)}</b> events</span><span><b>{len(ent.get("devices", []))}</b> devices</span>'
        f'<span><b>{len(links)}</b> rules matched</span></div>'
        f'<div class="tl-facts" style="margin-top:6px"><span>Addresses <b class="tl-mono">{ui.esc(", ".join(ent.get("ips", [])) or "-")}</b></span>'
        f'<span>Users <b>{ui.esc(", ".join(ent.get("users", [])) or "none")}</b></span>'
        f'<span>Devices <b>{ui.esc(", ".join(ent.get("devices", [])) or "-")}</b></span></div></div>',
        unsafe_allow_html=True)

    by_device = {}
    for f in facts:
        by_device.setdefault(f"{f.get('source_vendor')} {f.get('source_product')}", []).append(
            {"t": _ms(f.get("timestamp")), "severity_id": SEVERITY_ID.get(f.get("severity"), 2),
             "title": f.get("event_class"), "detail": f.get("fact_description")})
    times = [e["t"] for items in by_device.values() for e in items if e["t"]]
    if times:
        pad = max((max(times) - min(times)) // 20, 1000)
        with st.container(key="tile-rca-timeline"):
            st.markdown('<div class="tl-tile__title">Timeline</div>' + ui.lanes(list(by_device.items()), min(times) - pad,
                                                                                 max(times) + pad),
                        unsafe_allow_html=True)

    col_facts, col_inferred = st.columns(2, gap="medium")
    with col_facts:
        st.markdown('<div class="tl-subhead" style="border:0;padding-top:0">What was observed</div>', unsafe_allow_html=True)
        st.caption("Stored events, each with the SHA-256 of its raw line.")
        st.markdown("".join(
            f'<div class="tl-card"><div class="tl-card__head"><span>#{ui.esc(f.get("sequence_num"))} · '
            f'{ui.esc(f.get("source_vendor"))} · {ui.esc(f.get("event_class"))}</span>'
            f'{ui.sev_tag(SEVERITY_ID.get(f.get("severity"), 2), f.get("severity"))}</div>'
            f'<div class="tl-card__body">{ui.esc(f.get("fact_description"))}'
            f'<div class="tl-hash" style="margin-top:4px">{ui.esc((f.get("raw_hash") or "")[:32])}…</div></div></div>'
            for f in facts), unsafe_allow_html=True)

    with col_inferred:
        st.markdown('<div class="tl-subhead" style="border:0;padding-top:0">What the rules link</div>', unsafe_allow_html=True)
        st.caption("A match is not proof of cause, and it carries no probability.")
        if not links:
            st.info("No rule matched these events.")
        st.markdown("".join(
            f'<div class="tl-card tl-card--inferred"><div class="tl-card__head"><span>{ui.esc(RULES.get(inf.get("relationship_type"), inf.get("relationship_type")))}'
            f'</span><span class="tl-tile__aside">{len(inf.get("source_event_ids", []))} events</span></div>'
            f'<div class="tl-card__body"><ul>{"".join(f"<li>{ui.esc(e)}</li>" for e in inf.get("evidence", []))}</ul>'
            f'<div style="margin-top:6px"><b>Possible explanation:</b> {ui.esc(inf.get("hypothesis"))}</div>'
            f'<div style="margin-top:3px"><b>Limits:</b> {ui.esc(inf.get("rationale"))}</div></div></div>'
            for inf in links), unsafe_allow_html=True)

    recs = incident.get("recommendations") or []
    if recs:
        st.markdown('<div class="tl-subhead">Next steps</div>', unsafe_allow_html=True)
        st.markdown("\n".join(f"- {r}" for r in recs))
