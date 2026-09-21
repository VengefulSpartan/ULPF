"""
Connectors page: live status of every input and output, one-click test delivery,
and copy-paste setup for log sources, forwarders and downstream tools.
"""
import csv
import io
import json

import pandas as pd
import streamlit as st

from backend.config import settings
from backend.connectors.guides import DESTINATIONS, FORWARDERS, SOURCES, render
from backend.connectors.outputs import COMPATIBILITY
from backend.services.normalization.ocsf_export import to_ocsf
from frontend.api_client import APIClient


def _card(title: str, value: str, sub: str = "", color: str = "#0F172A") -> str:
    return (f'<div class="metric-card"><div class="metric-title">{title}</div>'
            f'<div class="metric-value" style="font-size:1.35rem; color:{color};">{value}</div>'
            f'<div class="metric-subtext">{sub}</div></div>')


def _ago(ts) -> str:
    if not ts:
        return "never"
    try:
        t = pd.Timestamp(ts)
        t = t.tz_localize("UTC") if t.tzinfo is None else t
        secs = int((pd.Timestamp.now(tz="UTC") - t).total_seconds())
    except Exception:
        return str(ts)
    if secs < 60:
        return f"{max(secs, 0)} s ago"
    if secs < 3600:
        return f"{secs // 60} min ago"
    return f"{secs // 3600} h ago"


def _live_status():
    status = APIClient.get_connectors()
    top = st.columns([4, 1])
    top[1].button("↻ Refresh", use_container_width=True, key="conn_refresh")
    if status is None:
        st.warning(
            f"The API server is not reachable at {settings.BACKEND_HOST}:{settings.BACKEND_PORT}. Inputs and "
            "outputs run inside it, so start it with `python run_app.py` or `docker compose up`."
        )
        return

    p = status["pipeline"]
    c = st.columns(5)
    c[0].markdown(_card("Received", f"{p['received']:,}", "lines from all inputs"), unsafe_allow_html=True)
    c[1].markdown(_card("Stored & chained", f"{p['ingested']:,}", "archived, parsed, OCSF"), unsafe_allow_html=True)
    c[2].markdown(_card("Throughput", f"{p['events_per_second_10s']:,}", "events/s, last 10 s"),
                  unsafe_allow_html=True)
    c[3].markdown(_card("Queue", f"{p['queue_depth']:,}", f"spooled to disk: {p['spooled']:,}"),
                  unsafe_allow_html=True)
    worker_ok = p.get("worker_alive")
    c[4].markdown(_card("Pipeline", "● Running" if worker_ok else "○ Idle", p.get("last_error") or "no errors",
                        "#2E7D32" if worker_ok else "#94A3B8"), unsafe_allow_html=True)

    st.markdown("##### Inputs: where logs arrive")
    rows = []
    for i in status["inputs"]:
        rows.append({"Input": i.get("name"), "Type": i.get("type"),
                     "Listening / path": i.get("listening") or ", ".join(i.get("paths", []) or []) or "HTTP API",
                     "Received": i.get("received", 0), "Bytes": i.get("bytes", 0),
                     "Last message": _ago(i.get("last_received_at")), "Errors": i.get("errors", 0),
                     "State": "running" if i.get("running", True) else "stopped"})
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    http = status["http_receivers"]
    st.caption(
        f"HTTP receivers ({'on' if http['enabled'] else 'off'}, authentication: {http['authentication']}): "
        + " · ".join(f"`{e}`" for e in http["endpoints"])
        + f" on port {settings.BACKEND_PORT}."
    )

    st.markdown("##### Outputs: where OCSF events go")
    outputs = status["outputs"]
    if not outputs:
        st.info("No outputs configured. Add one in config/tracelog.yaml (see the 'Connect a destination' tab).")
    for o in outputs:
        with st.container(border=True):
            left, mid, right = st.columns([3, 4, 1.4])
            alive = o.get("alive")
            left.markdown(f"**{o['name']}** &nbsp; `{o['type']}`  \n"
                          f"<span style='color:{'#2E7D32' if alive else '#B91C1C'}'>"
                          f"{'● delivering' if alive else '○ not running'}</span>", unsafe_allow_html=True)
            if o.get("error"):
                mid.error(o["error"])
            else:
                mid.markdown(
                    f"`{o.get('target', '')}`  \n"
                    f"sent **{o.get('sent', 0):,}** · failed {o.get('failed', 0):,} · dead-lettered "
                    f"{o.get('dead_lettered', 0):,} · retries {o.get('retries', 0):,} · queue {o.get('queue_depth', 0)}"
                    f"  \nlast success {_ago(o.get('last_success_at'))}"
                    + (f"  \n:red[last error: {o['last_error']}]" if o.get("last_error") else ""))
            if right.button("Send test event", key=f"test_{o['name']}", disabled=not alive,
                            use_container_width=True):
                res = APIClient.test_output(o["name"])
                (st.success if res.get("ok") else st.error)(f"{o['name']}: {res.get('detail')}")
                if res.get("ocsf_violations"):
                    st.warning("OCSF check: " + "; ".join(res["ocsf_violations"]))


def _connect_source():
    st.markdown("##### Point a device at TRACELOG")
    c1, c2, c3 = st.columns(3)
    host = c1.text_input("TRACELOG address the device can reach", value="192.0.2.10", key="src_host")
    port = c2.text_input("Syslog port", value="514",
                         help="514 with docker compose; 5514 when the server runs directly without root.")
    api_port = c3.text_input("API / HEC / OTLP port", value=str(settings.BACKEND_PORT))
    vals = {"host": host, "syslog_port": port, "api_port": api_port}

    kind = st.radio("What sends the logs?", ["Network / security device", "Existing forwarder or collector"],
                    horizontal=True, label_visibility="collapsed")
    guides = SOURCES if kind.startswith("Network") else FORWARDERS
    choice = st.selectbox("Choose", [g["name"] for g in guides], key=f"guide_{kind}")
    g = next(x for x in guides if x["name"] == choice)
    if g.get("transport"):
        st.caption(f"Transport: {g['transport']} · Parser pack: `{g.get('pack', '-')}`")
    for n, step in enumerate(g["steps"], 1):
        st.markdown(f"{n}. {render(step, **vals)}")
    if g.get("snippet"):
        st.code(render(g["snippet"], **vals), language=g.get("lang") or "text")
    st.info("The device appears under Sources automatically with its first message, named after its hostname "
            "(or its address). Check the Live status tab for the counters.")


def _connect_destination():
    st.markdown("##### Send OCSF events to the tools your SOC already uses")
    st.dataframe(pd.DataFrame(COMPATIBILITY).rename(columns={"output": "Output type", "reaches": "Reaches"}),
                 use_container_width=True, hide_index=True)
    choice = st.selectbox("Destination", [d["name"] for d in DESTINATIONS])
    d = next(x for x in DESTINATIONS if x["name"] == choice)
    st.caption(f"Output type: `{d['type']}`")
    for n, step in enumerate(d["steps"], 1):
        st.markdown(f"{n}. {step}")
    st.markdown("Add under `outputs:` in `config/tracelog.yaml`, set the environment variables, and restart:")
    st.code(d["config"], language="yaml")
    st.caption("Secrets stay in the environment (${VAR}). Every output has its own queue, retries with backoff, "
               "a dead-letter file, and optional filters by OCSF class, severity or source.")


def _export():
    st.markdown("##### Download OCSF events")
    st.caption("Strict OCSF 1.1.0 (epoch-millisecond time, type_uid, metadata, observables), as the outputs send it.")
    events = APIClient.list_events(limit=500).get("events", [])
    ocsf = [to_ocsf(e["normalized"]) for e in events if e.get("normalized")]
    c1, c2, c3 = st.columns(3)
    c1.download_button("📥 OCSF NDJSON", "\n".join(json.dumps(e) for e in ocsf) + ("\n" if ocsf else ""),
                       file_name="tracelog_ocsf.ndjson", mime="application/x-ndjson", use_container_width=True)
    c2.download_button("📥 OCSF JSON array", json.dumps(ocsf, indent=2), file_name="tracelog_ocsf.json",
                       mime="application/json", use_container_width=True)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["sequence_num", "time", "class_name", "severity", "src_ip", "dst_ip",
                                        "action", "raw_hash"])
    w.writeheader()
    for e in events:
        w.writerow({k: e.get(k) for k in w.fieldnames})
    c3.download_button("📥 Summary CSV", buf.getvalue(), file_name="tracelog_events.csv", mime="text/csv",
                       use_container_width=True)
    st.caption(f"Latest {len(ocsf)} events. For continuous export use a `file` or `parquet` output.")
    st.markdown(
        f"API documentation: [Swagger UI](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/docs) · "
        f"[ReDoc](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/redoc)"
    )


def render_integrations():
    st.markdown("## Connectors")
    st.caption("Plug-and-play: devices and forwarders stream in over syslog, Splunk HEC, OTLP, files or Kafka; "
               "normalised OCSF events stream out to SIEMs, observability platforms and data lakes.")
    tab_live, tab_src, tab_dst, tab_exp = st.tabs(
        ["📡 Live status", "🔌 Connect a log source", "🎯 Connect a destination", "💾 Export"])
    with tab_live:
        _live_status()
    with tab_src:
        _connect_source()
    with tab_dst:
        _connect_destination()
    with tab_exp:
        _export()
