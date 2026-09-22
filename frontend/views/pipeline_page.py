import pandas as pd
import streamlit as st

from frontend.api_client import APIClient


def _stage(col, name: str, count: str, badge: str, desc: str, ok: bool = True) -> None:
    col.markdown(
        f"""
        <div class="metric-card" style="border-top: 3px solid {'#0077B6' if ok else '#B91C1C'}; text-align: center;">
            <div class="metric-title">{name}</div>
            <div style="font-size: 1.4rem; font-weight: 700; color: #123B5D; margin: 6px 0;">{count}</div>
            <div class="badge {'badge-success' if ok else 'badge-error'}">{badge}</div>
            <div style="font-size: 0.72rem; color: #64748B; margin-top: 6px;">{desc}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pipeline():
    st.markdown("## Processing Pipeline")
    st.caption("Receive → archive raw line → parse → normalise to OCSF 1.1.0 → hash-chain → deliver. "
               "Every number on this page is measured from the database or the running server.")

    kpis = APIClient.get_overview()
    live = APIClient.get_connectors()  # None when the API server (inputs and outputs) is not running
    parsing = kpis.get("parsing") or {}
    conf = kpis.get("ocsf_conformance") or {}
    pipe = kpis.get("pipeline") or {}
    lp = (live or {}).get("pipeline") or {}

    cols = st.columns(6)
    _stage(cols[0], "1. Receive", f"{lp.get('received', 0):,}" if live else "–",
           f"{lp.get('events_per_second_10s', 0):,} events/s" if live else "server not running",
           "lines received since the server started", bool(live))
    _stage(cols[1], "2. Raw archive", f"{pipe.get('raw_archived', 0):,}", "SHA-256 per line",
           f"{pipe.get('streamed', 0):,} streamed, the rest uploaded or via the API")
    _stage(cols[2], "3. Parse", f"{parsing.get('total', 0):,}", f"{parsing.get('known_parser_pct', 0)}% known parser",
           f"generic {parsing.get('generic_pct', 0)}% · unparsed {parsing.get('unparsed_pct', 0)}%",
           parsing.get("unparsed_pct", 0) == 0)
    _stage(cols[3], "4. Normalise", f"{conf.get('checked', 0):,}", f"{conf.get('valid_pct', 0)}% OCSF-valid",
           "latest events checked against OCSF 1.1.0", not conf.get("checked") or conf.get("valid_pct") == 100)
    _stage(cols[4], "5. Hash chain", f"{pipe.get('hash_chained', 0):,}",
           "adds up" if pipe.get("consistent", True) else "MISMATCH",
           f"{pipe.get('revisions', 0):,} re-parse revisions included", pipe.get("consistent", True))
    outputs = (live or {}).get("outputs") or []
    waiting = sum(int(o.get("dead_letters", {}).get("waiting", 0) if isinstance(o.get("dead_letters"), dict)
                      else o.get("dead_letters") or 0) for o in outputs)
    _stage(cols[5], "6. Deliver", f"{len(outputs)}" if live else "–",
           f"{waiting:,} dead letters waiting" if live else "server not running",
           "configured outputs (see Connectors)", bool(live) and waiting == 0)

    st.markdown("---")
    col_stats, col_inspect = st.columns([1, 1])

    with col_stats:
        st.markdown("##### Which parser read the stored events")
        by_parser = parsing.get("by_parser") or {}
        if by_parser:
            total = max(parsing.get("total", 0), 1)
            names = {"generic_inferred": "generic (evidence only, unverified)", "parse_error": "parse error"}
            st.dataframe(pd.DataFrame([{"Parser": names.get(k, k), "Events": v, "Share": f"{100 * v / total:.1f}%"}
                                       for k, v in by_parser.items()]), use_container_width=True, hide_index=True)
        else:
            st.info("No events stored yet.")
        if live:
            st.markdown(f"**Live:** {lp.get('events_per_second_10s', 0):,} events/s over the last 10 s · queue "
                        f"{lp.get('queue_depth', 0):,} · spooled to disk {lp.get('spooled', 0):,} · failed batches "
                        f"{lp.get('failed_batches', 0):,}")
        for problem, n in conf.get("top_failures") or []:
            st.error(f"OCSF check failed on {n} of the latest events: {problem}")

    with col_inspect:
        st.markdown("##### Lines no parser could classify")
        unparsed = APIClient.get_unparsed(5)
        if not unparsed.get("total"):
            st.success("Every stored line was classified into an OCSF class.")
        else:
            st.caption(f"{unparsed['total']:,} events are OCSF Base Events: archived, hash-chained and forwarded, but "
                       "not classified. Formats no parser knows are listed in Parser Studio > New log formats.")
            for line in unparsed["lines"]:
                st.code(line["raw_text"][:400], language="text")
                st.caption(f"#{line['sequence_num']} · {line['source_name']} · parser: {line['parser']}"
                           + (f" · error: {line['parse_error']}" if line.get("parse_error") else ""))

        with st.expander("Send a malformed line through the pipeline"):
            malformed_sample = st.text_input("Malformed line",
                                             value="<9999>Invalid header with corrupt timestamps and broken key===values")
            if st.button("Process malformed line"):
                sources = APIClient.list_sources()
                if sources:
                    res = APIClient.ingest_single(malformed_sample, sources[0]["id"], "Test", "Device")
                    st.success(f"Archived with its SHA-256 and stored as sequence #{res.get('sequence_num')} "
                               f"(parser: {res.get('format_detected')}, class: {res.get('ocsf_class')}).")
                else:
                    st.warning("Load the sample dataset on the Overview page first.")
