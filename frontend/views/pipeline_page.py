import pandas as pd
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient


def _stage(step: int, name: str, count: str, status: str, desc: str, ok: bool = True) -> str:
    return (f'<article class="tl-kpi tl-stage"><div class="tl-kpi__label"><span class="tl-stage__n">{step}</span>'
            f'{ui.esc(name)}</div><div class="tl-kpi__value">{count}</div>'
            f'<div class="tl-stage__status"><span class="tl-dot tl-dot--{"good" if ok else "warning"}"></span>'
            f'{ui.esc(status)}</div><div class="tl-kpi__foot"><span>{ui.esc(desc)}</span></div></article>')


def render_pipeline():
    ui.page_header("Pipeline", "Receive, archive, parse, normalize, chain, deliver. Measured from the database "
                               "and the running server.")
    kpis = APIClient.get_overview()
    live = APIClient.get_connectors()  # None when the API server (inputs and outputs) is not running
    parsing = kpis.get("parsing") or {}
    conf = kpis.get("ocsf_conformance") or {}
    pipe = kpis.get("pipeline") or {}
    lp = (live or {}).get("pipeline") or {}
    outputs = (live or {}).get("outputs") or []
    waiting = sum(int(o.get("dead_letters", {}).get("waiting", 0) if isinstance(o.get("dead_letters"), dict)
                      else o.get("dead_letters") or 0) for o in outputs)
    consistent = pipe.get("consistent", True)

    stages = [
        _stage(1, "Receive", ui.num(lp.get("received", 0)) if live else "-",
               f"{lp.get('events_per_second_10s', 0):,} events/s" if live else "API not running",
               "lines since the server started", bool(live)),
        _stage(2, "Archive", ui.num(pipe.get("raw_archived", 0)), "SHA-256 per line",
               f"{pipe.get('streamed', 0):,} over the network"),
        _stage(3, "Parse", ui.num(parsing.get("total", 0)), f"{parsing.get('known_parser_pct', 0)}% by a known parser",
               f"generic {parsing.get('generic_pct', 0)}% · unparsed {parsing.get('unparsed_pct', 0)}%",
               parsing.get("unparsed_pct", 0) == 0),
        _stage(4, "Normalize", ui.num(conf.get("checked", 0)), f"{conf.get('valid_pct', 0)}% OCSF-valid",
               "latest events checked", not conf.get("checked") or conf.get("valid_pct") == 100),
        _stage(5, "Chain", ui.num(pipe.get("hash_chained", 0)), "counts match" if consistent else "counts differ",
               f"{pipe.get('revisions', 0):,} re-parse revisions included", consistent),
        _stage(6, "Deliver", ui.num(len(outputs)) if live else "-",
               f"{waiting:,} dead letters waiting" if live else "API not running",
               "outputs configured", bool(live) and waiting == 0),
    ]
    st.markdown(f'<div class="tl-flow">{"".join(stages)}</div>', unsafe_allow_html=True)
    st.space("small")

    col_stats, col_inspect = st.columns(2, gap="medium")
    with col_stats.container(key="tile-pipe-parsers"):
        st.markdown('<div class="tl-tile__title">Parsers used</div>', unsafe_allow_html=True)
        by_parser = parsing.get("by_parser") or {}
        if by_parser:
            total = max(parsing.get("total", 0), 1)
            names = {"generic_inferred": "generic (evidence only, unverified)", "parse_error": "parse error"}
            st.dataframe(pd.DataFrame([{"Parser": names.get(k, k), "Events": v, "Share": f"{100 * v / total:.1f}%"}
                                       for k, v in by_parser.items()]), width="stretch", hide_index=True)
        else:
            st.info("No events stored yet.")
        if live:
            st.caption(f"Now: {lp.get('events_per_second_10s', 0):,} events/s over the last 10 s · queue "
                       f"{lp.get('queue_depth', 0):,} · spooled to disk {lp.get('spooled', 0):,} · failed batches "
                       f"{lp.get('failed_batches', 0):,}")
        for problem, n in conf.get("top_failures") or []:
            st.error(f"OCSF check failed on {n} of the latest events: {problem}")

    with col_inspect.container(key="tile-pipe-unparsed"):
        st.markdown('<div class="tl-tile__title">Lines no parser could classify</div>', unsafe_allow_html=True)
        unparsed = APIClient.get_unparsed(5)
        if not unparsed.get("total"):
            st.success("Every stored line has an OCSF class.")
        else:
            n = unparsed["total"]
            st.caption(f"{n:,} {'event is an OCSF Base Event' if n == 1 else 'events are OCSF Base Events'}: archived, "
                       "chained and forwarded, but not classified. New formats are listed in Parser Studio.")
            for line in unparsed["lines"]:
                st.code(line["raw_text"][:400], language="text")
                st.caption(f"#{line['sequence_num']} · {line['source_name']} · parser: {line['parser']}"
                           + (f" · error: {line['parse_error']}" if line.get("parse_error") else ""))

        with st.expander("Send a malformed line"):
            malformed_sample = st.text_input("Line", value="<9999>Invalid header with corrupt timestamps and broken key===values")
            if st.button("Send it"):
                sources = APIClient.list_sources()
                if sources:
                    res = APIClient.ingest_single(malformed_sample, sources[0]["id"], "Test", "Device")
                    st.success(f"Stored as #{res.get('sequence_num')} with its SHA-256 "
                               f"(parser: {res.get('format_detected')}, class: {res.get('ocsf_class')}).")
                else:
                    st.warning("Load the sample data on the Overview page first.")
