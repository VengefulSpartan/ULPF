"""Overview: everything that needs a glance, on one screen.

Row 1 is the state of the archive (how much, how well parsed, OCSF-valid, chain consistent, what was
detected, what has no parser yet). Rows 2 and 3 are the selected time range: traffic and denials with
the detections marked, where events come from, the newest detections, the event classes and the
addresses denied most. The range ends at the newest stored event, so an imported day still shows.
"""
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient

RANGES = {"1 h": 1, "6 h": 6, "24 h": 24, "7 d": 168, "All": 0}


@st.cache_data(ttl=10, show_spinner=False)
def _overview():
    return APIClient.get_overview()


@st.cache_data(ttl=10, show_spinner=False)
def _activity(hours):
    return APIClient.get_activity(hours)


def _load_samples():
    res = APIClient.seed_samples()
    _overview.clear()
    _activity.clear()
    st.toast(f"Loaded {res.get('ingested_count', 0)} sample events.")


@st.fragment(run_every=30)
def render_overview():
    kpis = _overview()
    total = kpis.get("total_events", 0)

    choice = st.session_state.get("overview_range") or "24 h"
    act = _activity(RANGES[choice]) if total else {}
    window = act.get("window") or {}
    meta = (f"<b>{ui.num(total)}</b> events stored · newest {ui.utc(window.get('to_ms'))} UTC · refreshes every 30 s"
            if total else "Nothing stored yet")
    controls = ui.page_header("Overview", meta, controls=0.46)
    if not total:
        with st.container(key="tile-empty"):
            st.markdown('<div class="tl-empty"><b>Nothing stored yet</b><span>Point a firewall\'s syslog at port 514 '
                        f'({ui.link("how to connect a device", "connectors")}), or load eight sample events from '
                        'Palo Alto, Cisco ASA, FortiGate VPN and Suricata.</span></div>', unsafe_allow_html=True)
            st.button("Load sample data", type="primary", key="load_samples_empty", on_click=_load_samples)
        return
    with controls:
        st.segmented_control("Time range", list(RANGES), default="24 h", key="overview_range",
                             label_visibility="collapsed", required=True)
        st.button("Load sample data", key="load_samples", on_click=_load_samples,
                  help="Eight more events from four vendors: Palo Alto, Cisco ASA, FortiGate VPN and Suricata.")

    st.markdown(_grid(kpis, act), unsafe_allow_html=True)
    for problem, n in (kpis.get("ocsf_conformance") or {}).get("top_failures") or []:
        st.error(f"OCSF check failed on {n} of the latest events: {problem}")


def _grid(kpis: dict, act: dict) -> str:
    total = kpis.get("total_events", 0)
    parsing = kpis.get("parsing") or {}
    conf = kpis.get("ocsf_conformance") or {}
    pipe = kpis.get("pipeline") or {}
    fresh = kpis.get("new_formats") or {}
    window, totals = act.get("window") or {}, act.get("totals") or {}
    timeline = act.get("timeline") or []

    # ---- row 1: the archive
    known = parsing.get("known_parser_pct", 0.0)
    generic = parsing.get("generic", 0)
    valid, checked = conf.get("valid_pct", 0.0), conf.get("checked", 0)
    consistent = pipe.get("consistent", True)
    sev = {r["id"]: r["events"] for r in act.get("findings_by_severity") or []}
    high = sum(v for k, v in sev.items() if k >= 4)
    formats, format_lines = fresh.get("formats", 0), fresh.get("lines", 0)
    cards = [
        ui.kpi("Events stored", ui.num(total),
               f'<span>{ui.compact(totals.get("events", 0))} in range</span>'
               + ui.sparkline([p["events"] for p in timeline])),
        ui.kpi("Parsed by a known parser", ui.pct(known), f"<span>{ui.num(generic)} by the generic parser</span>",
               extra=ui.meter(known)),
        ui.kpi("OCSF 1.1.0 checks passed", ui.pct(valid) if checked else "-",
               f"<span>latest {ui.num(checked)} events checked</span>", extra=ui.meter(valid if checked else 0)),
        ui.kpi("Integrity chain", "Consistent" if consistent else "Counts differ",
               f'<span>{ui.num(kpis.get("ledger_entries", 0))} records</span>{ui.link("Verify", "integrity")}',
               dot="good" if consistent else "critical"),
        ui.kpi("Detections in range", ui.num(totals.get("findings", 0)),
               f"<span>{ui.num(high)} high or critical</span>{ui.link('Investigate', 'correlation')}",
               extra=ui.severity_bar(act.get("findings_by_severity") or [])),
        ui.kpi("Formats without a parser", ui.num(formats),
               f"<span>{ui.num(format_lines)} lines</span>" + (ui.link("Review", "parser-studio") if formats else ""),
               dot="warning" if formats else "good"),
    ]

    # ---- row 2: traffic over time, and where it comes from
    step = window.get("bucket_ms") or 60_000
    start = window.get("from_ms") or 0
    marks = {}
    for f in act.get("findings") or []:
        i = (f["time_ms"] - start) // step
        m = marks.setdefault(i, {"count": 0, "worst_id": 0, "titles": []})
        m["count"] += 1
        m["worst_id"] = max(m["worst_id"], f.get("severity_id") or 0)
        who = f.get("src_ip") or f.get("user") or ""
        m["titles"].append(f'{f.get("title") or "Detection"}{" · " + who if who else ""}')
    for m in marks.values():
        m["worst"] = ui.severity_class(m["worst_id"])
    span = f'{ui.utc(window.get("from_ms"))} to {ui.utc(window.get("to_ms"))} UTC'
    traffic = ui.tile(
        "Events over time", ui.timeseries(timeline, step, marks, label=f"Events and denials per time slot, {span}"),
        aside='<span style="display:flex;gap:14px;align-items:center">'
              + ui.legend([("Events", "c1", "line"), ("Denied", "c2", "line"), ("Detection", "sv-high", "dia")])
              + ui.timeseries_table(timeline, step) + "</span>",
        span=8)
    sources = act.get("by_source") or []
    where = ui.tile(
        "Sources", ui.bar_list([(s["name"], s["events"]) for s in sources], limit=5)
        + '<div class="tl-subhead">Event classes (OCSF)</div>'
        + ui.parts([(c["name"], c["events"]) for c in act.get("by_class") or []], limit=4, inline=True),
        aside=f"{len(sources)} in range", span=4)

    # ---- row 3: newest detections, and the addresses denied most
    rows = []
    for f in (act.get("findings") or [])[:14]:
        who = f.get("src_ip") or f.get("user") or "-"
        rows.append([f'<td class="t">{ui.utc(f["time_ms"], "%d %b %H:%M")}</td>',
                     f'<td title="{ui.esc(f.get("title"))}">{ui.esc(f.get("title") or "Detection")}</td>',
                     f'<td class="m">{ui.esc(who)}</td>',
                     f'<td>{ui.esc(f.get("source") or "")}</td>',
                     f'<td>{ui.sev_tag(f.get("severity_id"), f.get("severity"))}</td>'])
    detections = ui.tile(
        "Newest detections",
        ui.table([("Time (UTC)", "96px"), ("Detection", ""), ("Address or user", "132px"), ("Reported by", "22%"),
                  ("Severity", "84px")], rows)
        if rows else ui.empty("No detections in this range"),
        aside=ui.link("Open in Log Explorer", "log-explorer"), span=8)
    denied = act.get("top_denied") or []
    most_denied = ui.tile("Most denied addresses",
                          ui.bar_list([(d["src_ip"], d["events"]) for d in denied], color=2, mono=True),
                          aside=f"{ui.num(totals.get('denied', 0))} denied in range", span=4)

    return (f'<div class="tl-dash"><section class="tl-kpis">{"".join(cards)}</section>'
            f'<section class="tl-row">{traffic}{where}</section>'
            f'<section class="tl-row">{detections}{most_denied}</section></div>')
