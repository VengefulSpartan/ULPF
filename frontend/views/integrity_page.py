from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient

ISSUES = {
    "SEQUENCE_GAP_OR_REORDER": "A record is missing or out of order here.",
    "RAW_PAYLOAD_MISSING": "The raw line of this record is missing.",
    "RAW_HASH_MISMATCH": "The raw line no longer matches its hash.",
    "BROKEN_CHAIN": "This record does not link to the one before it.",
    "NORMALIZED_DATA_MISSING": "The normalized event of this record is missing.",
    "HASH_MISMATCH": "The stored event no longer matches its hash: it was changed after it was chained.",
}


def _verify() -> None:
    st.session_state["chain_check"] = (APIClient.verify_integrity(), datetime.now(timezone.utc).strftime("%H:%M:%S"))


def render_integrity():
    ui.page_header("Integrity", "Each event is chained to the one before it with SHA-256. Changing, removing or "
                                "reordering a record breaks the chain from that record on.")
    top = st.columns([1, 4], vertical_alignment="center")
    top[0].button("Verify the chain", type="primary", on_click=_verify, width="stretch")
    top[1].caption("A valid chain proves the records were not changed, removed or reordered after TRACELOG stored "
                   "them. It cannot prove the sending device told the truth or sent everything.")
    if "chain_check" not in st.session_state:
        with st.spinner("Verifying the chain…"):
            _verify()   # once per session; after that only on request, since a long chain takes a while
    res, checked_at = st.session_state["chain_check"]
    total, failed = res.get("total_records", 0), res.get("failed_records", 0)
    time_ms = res.get("verification_time_ms", 0.0)
    if res.get("is_valid", True):
        verdict = ui.kpi("Result", "Chain intact", f"<span>every record matches its hash and link · checked {checked_at} UTC"
                                                   "</span>", dot="good")
    else:
        verdict = ui.kpi("Result", f"Broken at record #{res.get('first_corrupted_seq')}",
                         f"<span>checked {checked_at} UTC</span>", dot="critical")
    st.markdown(
        '<div class="tl-kpis" style="grid-template-columns: 2fr 1fr 1fr 1fr 1fr">' + verdict
        + ui.kpi("Records checked", ui.num(total)) + ui.kpi("Valid", ui.num(res.get("verified_records", 0)))
        + ui.kpi("Failed", ui.num(failed), dot="critical" if failed else None)
        + ui.kpi("Time", f"{time_ms:,.0f} <small>ms</small>") + "</div>", unsafe_allow_html=True)
    for iss in res.get("issues", []):
        st.error(f"**Record #{iss.get('sequence_num')}**: {ISSUES.get(iss.get('issue_type'), iss.get('description'))}\n\n"
                 f"Expected `{iss.get('expected')}`\n\nFound `{iss.get('actual')}`")

    ledger_records = APIClient.get_ledger(limit=50)
    left, right = st.columns([2, 3], gap="medium")
    with left.container(key="tile-int-tamper"):
        st.markdown('<div class="tl-tile__title">Tamper test</div>', unsafe_allow_html=True)
        st.caption("Changes one stored record directly in the database, as someone with database access could. "
                   "The next verification names the record. For demonstrations only.")
        if not ledger_records:
            st.info("Nothing stored yet. Load the sample data first.")
        else:
            target_seq = st.selectbox("Record", [r["sequence_num"] for r in ledger_records])
            tamper_val = st.text_input("New value for disposition", value="allowed")
            b1, b2 = st.columns(2)
            if b1.button("Change the record", width="stretch"):
                res = APIClient.simulate_tamper(sequence_num=target_seq, value=tamper_val)
                if "error" in res:
                    st.error(res["error"])
                else:
                    st.warning(f"Record #{target_seq} changed: disposition was '{res.get('original_value')}', now "
                               f"'{res.get('tampered_value')}'. Verify the chain to see it caught.")
            if b2.button("Restore the record", width="stretch"):
                res = APIClient.restore_record(sequence_num=target_seq)
                if "error" in res:
                    st.error(res["error"])
                else:
                    st.success(f"Record #{target_seq} restored.")

    with right.container(key="tile-int-records"):
        st.markdown('<div class="tl-tile__title">Newest chain records</div>', unsafe_allow_html=True)
        if ledger_records:
            cols = {"sequence_num": "#", "raw_hash": "Raw line hash", "record_hash": "Record hash",
                    "prev_hash": "Previous record hash", "timestamp": "Chained at"}
            df = pd.DataFrame(ledger_records)
            st.dataframe(df[[c for c in cols if c in df.columns]].rename(columns=cols), width="stretch",
                         hide_index=True, height=300)
        else:
            st.info("Nothing stored yet.")
