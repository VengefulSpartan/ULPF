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
            failing = alive and o.get("last_error_at") and (o.get("last_error_at") > (o.get("last_success_at") or ""))
            state, color = (("○ not running", "#B91C1C") if not alive else
                            ("● failing: events go to dead letters", "#C2410C") if failing else
                            ("● delivering", "#2E7D32"))
            left.markdown(f"**{o['name']}** &nbsp; `{o['type']}`  \n"
                          f"<span style='color:{color}'>{state}</span>", unsafe_allow_html=True)
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
            dl = o.get("dead_letters") or {}
            if dl.get("waiting"):
                _dead_letter_panel(o["name"], dl, [x["name"] for x in outputs if x.get("alive")])

    orphans = [d for d in (APIClient.get_dead_letters() or []) if not d.get("configured") and d.get("waiting")]
    if orphans:
        st.markdown("##### Dead letters from outputs no longer in the configuration")
        for d in orphans:
            with st.container(border=True):
                st.markdown(f"**{d['output']}** · {d['waiting']:,} events waiting · oldest {d.get('oldest') or '-'}")
                _dead_letter_panel(d["output"], {"waiting": d["waiting"], "by_kind": d["by_kind"]},
                                   [x["name"] for x in outputs if x.get("alive")], orphan=True)


_KIND_HELP = {
    "undeliverable": "every retry failed (destination down, timeout, 5xx/429). Safe to re-send as is.",
    "queue_full": "the output's queue overflowed during a burst. Safe to re-send as is.",
    "rejected": "the destination refused them (4xx: token, mapping, size). Fix the cause, then re-send.",
}


def _dead_letter_panel(name: str, dl: dict, running_outputs: list, orphan: bool = False):
    kinds = dl.get("by_kind") or {}
    parts = [f"{k.replace('_', ' ')} {n:,}" for k, n in kinds.items() if n]
    auto = "" if orphan else (" · re-sent automatically when the destination answers"
                              if dl.get("auto_replay") else " · automatic re-send off")
    st.warning(f"{dl['waiting']:,} dead letters waiting ({', '.join(parts)}){auto}")
    last = dl.get("last_replay")
    if last:
        st.caption(f"Last re-send ({last.get('trigger')}): {last.get('state')}, {last.get('delivered', 0):,} delivered"
                   + (f", error: {last['error']}" if last.get("error") else ""))
    with st.expander(f"Inspect and re-send · {name}"):
        detail = APIClient.dead_letter_entries(name, limit=8)
        summ = detail.get("summary") or {}
        for k, n in kinds.items():
            if n:
                st.markdown(f"- **{k.replace('_', ' ')}** ({n:,}): {_KIND_HELP[k]}")
        if summ.get("top_reasons"):
            st.markdown("**Why:** " + " · ".join(f"{r['reason']} ({r['count']})" for r in summ["top_reasons"][:3]))
        if summ.get("by_source"):
            st.markdown("**From:** " + ", ".join(f"{s} ({n})" for s, n in list(summ["by_source"].items())[:5]))
        rows = [{"at": e.get("at", "")[:19], "kind": e.get("kind"), "attempts": e.get("attempts"),
                 "class": (e.get("event") or {}).get("class_name"), "source": e.get("source"),
                 "reason": (e.get("reason") or "")[:90]} for e in detail.get("entries", [])]
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        c1, c2, c3 = st.columns([2, 2, 1])
        pick = c1.multiselect("Kinds to re-send", [k for k, n in kinds.items() if n],
                              default=[k for k, n in kinds.items() if n], key=f"dl_kinds_{name}")
        options = running_outputs if orphan else [name] + [x for x in running_outputs if x != name]
        via = c2.selectbox("Send through output", options, key=f"dl_via_{name}") if options else None
        limit = c3.number_input("Max events (0 = all)", min_value=0, value=0, step=100, key=f"dl_limit_{name}")
        if st.button(f"Re-send dead letters", key=f"dl_go_{name}", type="primary", disabled=not (pick and via)):
            res = APIClient.replay_dead_letters(name, to=via, kinds=pick, limit=int(limit) or None)
            state = res.get("state")
            msg = (f"{state}: {res.get('delivered', 0):,} delivered, {res.get('refused_again', 0):,} refused again, "
                   f"{res.get('remaining', '?')} still waiting")
            if state == "done":
                st.success(msg)
            elif state in ("limit_reached", "running", "queued"):
                st.info(msg)
            else:
                st.error(msg + (f" · {res.get('error')}" if res.get("error") else ""))


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
        f"API documentation: [Swagger UI](http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}/docs) "
        "(served by TRACELOG itself, so it works without internet access)"
    )


def _reconcile_view():
    st.markdown("##### Is every log line accounted for?")
    st.caption("Every stored event, at every output: delivered, excluded by the output's filter, waiting in dead "
               "letters, or in flight. Each outcome is a record in a hash-chained delivery ledger, so the numbers "
               "below can be proven, not just displayed.")
    top = st.columns([1, 1, 3])
    top[0].button("↻ Re-check", key="rec_refresh", use_container_width=True)
    if top[1].button("🧾 Generate audit report", key="rec_report", type="primary", use_container_width=True):
        with st.spinner("Verifying both chains and building the report..."):
            st.session_state["audit_pdf"] = APIClient.get_audit_report("pdf")
            st.session_state["audit_json"] = APIClient.get_audit_report("json")
    pdf, js = st.session_state.get("audit_pdf"), st.session_state.get("audit_json")
    if pdf or js:
        with top[2]:
            d1, d2 = st.columns(2)
            if pdf and pdf.get("ok"):
                d1.download_button("📄 Download PDF", pdf["data"], file_name=pdf["filename"], mime="application/pdf",
                                   use_container_width=True, key="dl_pdf")
            elif pdf:
                d1.error(pdf.get("error"))
            if js and js.get("ok"):
                d2.download_button("{ } Download JSON", js["data"], file_name=js["filename"],
                                   mime="application/json", use_container_width=True, key="dl_json")
            elif js:
                d2.error(js.get("error"))

    rec = APIClient.get_reconciliation()
    if rec is None:
        st.warning("The API server is not reachable, so there is nothing to reconcile yet.")
        return
    (st.success if rec["all_accounted"] else st.error)(rec["verdict"])

    p, integ, deliv = rec["pipeline"], rec.get("integrity") or {}, rec.get("delivery_ledger") or {}
    c = st.columns(5)
    c[0].markdown(_card("Archived raw", f"{p['raw_archived']:,}", "lines, byte-for-byte"), unsafe_allow_html=True)
    revs = p.get("revisions", 0)
    c[1].markdown(_card("Normalised", f"{p['normalized']:,}",
                        f"OCSF 1.1.0 events, {revs:,} re-parse revisions" if revs else "OCSF 1.1.0 events"),
                  unsafe_allow_html=True)
    c[2].markdown(_card("Hash-chained", f"{p['hash_chained']:,}",
                        ("one per line plus revisions" if revs else "same size as archive") if p["consistent"]
                        else "counts do not add up",
                        "#0F172A" if p["consistent"] else "#B91C1C"), unsafe_allow_html=True)
    c[3].markdown(_card("Integrity chain", "valid" if integ.get("is_valid") else "FAILED",
                        f"{integ.get('verified_records', 0):,} records verified",
                        "#2E7D32" if integ.get("is_valid") else "#B91C1C"), unsafe_allow_html=True)
    c[4].markdown(_card("Delivery ledger", "valid" if deliv.get("is_valid") else "FAILED",
                        f"{deliv.get('batches', 0):,} chained records",
                        "#2E7D32" if deliv.get("is_valid") else "#B91C1C"), unsafe_allow_html=True)

    st.markdown("##### Per output")
    rows = [{"Output": o["output"], "Owed": o["owed"], "Delivered": o["delivered"], "Re-sent": o["resent"],
             "Via other": o["rerouted"], "Filtered": o["filtered"], "Dead letters": o["dead_letter_waiting"],
             "In flight": o["in_flight"], "Unaccounted": o["unaccounted"], "Dupes": o["duplicates"],
             "Status": "✅ balanced" if o["status"] == "balanced" else "❌ unaccounted"} for o in rec["outputs"]]
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No outputs have been configured yet.")
    st.caption("Owed = stored events since the output was first configured = delivered (re-sent ones included) + "
               "delivered via another output + filtered out + waiting in dead letters + in flight + unaccounted. "
               "Unaccounted must be 0. Dupes counts events delivered more than once (at-least-once re-sends).")
    for o in rec["outputs"]:
        for n in o["notes"]:
            st.caption(f"**{o['output']}**: {n}")
    r = rec.get("recovery") or {}
    if r.get("requeued") or r.get("filtered"):
        st.info(f"After the last restart, {r.get('requeued', 0):,} events that outputs still owed were sent again "
                f"from the archive ({r.get('state')}).")

    ex = rec.get("exceptions") or []
    st.markdown("##### Delivery exceptions (newest first)")
    if ex:
        st.dataframe(pd.DataFrame([{
            "From (UTC)": e["from"][:19].replace("T", " "), "To": e["to"][11:19], "Output": e["output"],
            "Outcome": e["outcome"].replace("_", " "), "Trigger": e["trigger"], "Batches": e["batches"],
            "Events": e["count"], "Detail": e["detail"]} for e in ex]), use_container_width=True, hide_index=True)
    else:
        st.caption("None: every batch was delivered at the first attempt.")


def render_integrations():
    st.markdown("## Connectors")
    st.caption("Plug-and-play: devices and forwarders stream in over syslog, Splunk HEC, OTLP, files or Kafka; "
               "normalised OCSF events stream out to SIEMs, observability platforms and data lakes.")
    tab_live, tab_rec, tab_src, tab_dst, tab_exp = st.tabs(
        ["📡 Live status", "🧾 Reconcile & audit", "🔌 Connect a log source", "🎯 Connect a destination", "💾 Export"])
    with tab_live:
        _live_status()
    with tab_rec:
        _reconcile_view()
    with tab_src:
        _connect_source()
    with tab_dst:
        _connect_destination()
    with tab_exp:
        _export()
