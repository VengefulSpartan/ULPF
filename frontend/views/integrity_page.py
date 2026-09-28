from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from backend.config import settings
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
ALGS = {"ed25519": "Ed25519", "ml-dsa-65": "ML-DSA-65"}
WHO = ["Someone with database access", "An insider with the server's keys"]


def _at() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _verify() -> None:
    st.session_state["chain_check"] = (APIClient.verify_integrity(), _at())


def _check_checkpoints() -> None:
    st.session_state["cp_check"] = (APIClient.get_checkpoints(), _at())


def _seal() -> None:
    res = APIClient.seal_checkpoints()
    if "error" in res:
        st.session_state["cp_note"] = ("error", res["error"])
    else:
        sealed = res.get("sealed") or []
        refused = [f"{w.get('witness') or url}: {w.get('error')}" for url, w in (res.get("witnesses") or {}).items()
                   if w.get("error")]
        st.session_state["cp_note"] = ("info", (f"Sealed {len(sealed)} new checkpoint(s)." if sealed else
                                                "Every record was already sealed.")
                                       + (" " + "; ".join(refused) if refused else ""))
    _check_checkpoints()


def _chain_kpis() -> None:
    res, checked_at = st.session_state["chain_check"]
    total, failed = res.get("total_records", 0), res.get("failed_records", 0)
    if res.get("is_valid", True):
        verdict = ui.kpi("Hash chain", "Intact", f"<span>every record matches its hash and link · {checked_at} UTC"
                                                 "</span>", dot="good")
    else:
        verdict = ui.kpi("Hash chain", f"Broken at #{res.get('first_corrupted_seq')}",
                         f"<span>checked {checked_at} UTC</span>", dot="critical")
    st.markdown(
        '<div class="tl-kpis" style="grid-template-columns: 2fr 1fr 1fr 1fr 1fr">' + verdict
        + ui.kpi("Records checked", ui.num(total)) + ui.kpi("Valid", ui.num(res.get("verified_records", 0)))
        + ui.kpi("Failed", ui.num(failed), dot="critical" if failed else None)
        + ui.kpi("Time", f"{res.get('verification_time_ms', 0.0):,.0f} <small>ms</small>") + "</div>",
        unsafe_allow_html=True)
    for iss in res.get("issues", []):
        st.error(f"**Record #{iss.get('sequence_num')}**: {ISSUES.get(iss.get('issue_type'), iss.get('description'))}\n\n"
                 f"Expected `{iss.get('expected')}`\n\nFound `{iss.get('actual')}`")


def _checkpoint_kpis() -> dict:
    cp, checked_at = st.session_state["cp_check"]
    if "error" in cp:
        st.warning(f"Checkpoints could not be checked: {cp['error']}")
        return {}
    problems, n = cp.get("problems") or [], cp.get("checkpoints", 0)
    if problems:
        first = next((p["index"] for p in problems if p.get("index")), None)
        verdict = ui.kpi("Signed checkpoints", f"Problem at #{first}" if first else "Problem",
                         f"<span>{len(problems)} finding(s) · {checked_at} UTC</span>", dot="critical")
    elif n:
        verdict = ui.kpi("Signed checkpoints", "Consistent", f"<span>roots, links and signatures match · {checked_at} UTC"
                                                            "</span>", dot="good")
    else:
        verdict = ui.kpi("Signed checkpoints", "None yet", "<span>select Seal now</span>", dot="warning")
    names = [ALGS.get(a, a) for a in cp.get("algorithms") or []]
    algs = (names[0] + "".join(f" <small>+ {n}</small>" for n in names[1:])) if names else "-"
    ws, configured = cp.get("witnesses") or [], cp.get("witnesses_configured", 0)
    if not configured:
        witness = ui.kpi("Witnesses", "None", "<span>set WITNESS_URLS: without them a re-signed history "
                                              "cannot be told apart</span>", dot="warning")
    else:
        agree = [w for w in ws if w.get("reachable") and not w.get("differ") and not w.get("missing_here")]
        differ = [w for w in ws if w.get("differ") or w.get("missing_here")]
        pending = sum(w.get("pending", 0) for w in ws)
        witness = ui.kpi("Witnesses", f"{len(agree)} of {configured} agree",
                         f"<span>{ui.esc(', '.join(w.get('witness') or w['url'] for w in ws if w.get('reachable')) or 'none reachable')}"
                         + (f" · {pending} waiting" if pending else "") + "</span>",
                         dot="critical" if differ else "good" if len(agree) == configured else "warning")
    st.markdown(
        '<div class="tl-kpis" style="grid-template-columns: 2fr 1fr 1.2fr 1.4fr; margin-top: 10px">' + verdict
        + ui.kpi("Records sealed", ui.num(cp.get("sealed_records", 0)),
                 f"<span>{ui.num(cp.get('unsealed_records', 0))} waiting · {ui.num(n)} checkpoints</span>")
        + ui.kpi("Signatures", algs, f"<span>node key {ui.esc(cp.get('node_key_id') or '-')}</span>")
        + witness + "</div>", unsafe_allow_html=True)
    if settings.HOSTED_DEMO and configured:
        st.caption(ui.HOSTED_WITNESSES_NOTE)
    for p in problems:
        st.error((f"**Checkpoint #{p['index']}**: " if p.get("index") else "") + p["problem"])
    return cp


def render_integrity():
    ui.page_header("Integrity", "A SHA-256 chain links every record to the one before it. Signed checkpoints seal "
                                "runs of records under a Merkle root, countersigned by witnesses on other machines.")
    top = st.columns([1, 1, 1, 3], vertical_alignment="center")
    top[0].button("Verify the chain", type="primary", on_click=_verify, width="stretch")
    top[1].button("Check the checkpoints", on_click=_check_checkpoints, width="stretch")
    top[2].button("Seal now", on_click=_seal, width="stretch",
                  help="Seal every record not yet in a checkpoint and send the new checkpoints to the witnesses. "
                       "The collector also does this on its own every few minutes.")
    top[3].caption("Together they prove the records were not changed, removed or reordered after TRACELOG stored "
                   "them. They cannot prove the sending device told the truth or sent everything.")
    if "chain_check" not in st.session_state:
        with st.spinner("Verifying the chain…"):
            _verify()   # once per session; after that only on request, since a long chain takes a while
    if "cp_check" not in st.session_state:
        with st.spinner("Checking the checkpoints…"):
            _check_checkpoints()
    note = st.session_state.pop("cp_note", None)
    if note:
        (st.error if note[0] == "error" else st.info)(note[1])

    _chain_kpis()
    cp = _checkpoint_kpis()

    ledger_records = APIClient.get_ledger(limit=50)
    left, right = st.columns([2, 3], gap="medium")
    with left.container(key="tile-int-tamper"):
        st.markdown('<div class="tl-tile__title">Tamper test</div>', unsafe_allow_html=True)
        who = st.segmented_control("Who changes the record", WHO, default=WHO[0], required=True, key="tamper_who",
                                   label_visibility="collapsed")
        if who == WHO[0]:
            st.caption("Changes one stored record directly in the database. Verify the chain and it names the record.")
        else:
            st.caption("Changes one record, recomputes every record hash after it so the chain checks out again, and "
                       "re-signs the checkpoints with this server's key. Only the witnesses still hold the original. "
                       "For demonstrations only.")
        if not ledger_records:
            st.info("Nothing stored yet. Load the sample data first.")
        else:
            target_seq = st.selectbox("Record", [r["sequence_num"] for r in ledger_records])
            tamper_val = st.text_input("New value for disposition", value="allowed")
            b1, b2 = st.columns(2)
            if who == WHO[0]:
                if b1.button("Change the record", width="stretch"):
                    res = APIClient.simulate_tamper(sequence_num=target_seq, value=tamper_val)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.warning(f"Record #{target_seq} changed: disposition was '{res.get('original_value')}', "
                                   f"now '{res.get('tampered_value')}'. Verify the chain to see it caught.")
                if b2.button("Restore the record", width="stretch"):
                    res = APIClient.restore_record(sequence_num=target_seq)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.success(f"Record #{target_seq} restored.")
            else:
                if b1.button("Rewrite history", width="stretch"):
                    res = APIClient.rewrite_history(target_seq, tamper_val)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        refused = [w.get("error") for w in (res.get("witnesses") or {}).values() if w.get("error")]
                        st.warning(f"Record #{target_seq}: disposition '{res.get('original_value')}' is now "
                                   f"'{res.get('new_value')}'. {res.get('records_rehashed')} record hashes recomputed, "
                                   f"{res.get('checkpoints_resigned')} checkpoint(s) re-signed. Verify the chain (it "
                                   f"passes), then check the checkpoints.")
                        for r in refused:
                            st.info(f"A witness answered: {r}")
                if b2.button("Restore history", width="stretch"):
                    res = APIClient.restore_history()
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.success(f"Record #{res.get('sequence_num')} and every hash after it restored.")

    with right.container(key="tile-int-records"):
        tab_cp, tab_chain = st.tabs(["Newest checkpoints", "Newest chain records"])
        with tab_cp:
            latest = (cp or {}).get("latest") or []
            if latest:
                rows = [[f'<td class="m">#{c["index"]}</td>',
                         f'<td class="m">#{c["first_seq"]} to #{c["last_seq"]}</td>',
                         f'<td class="m" title="{ui.esc(c["merkle_root"])}">{ui.esc(c["merkle_root"][:20])}…</td>',
                         f'<td>{ui.esc(", ".join(c.get("signers") or []))}</td>',
                         f'<td class="t">{ui.esc((c.get("sealed_at") or "")[11:19])}</td>'] for c in latest]
                st.markdown(ui.table([("#", "52px"), ("Records", "150px"), ("Merkle root", ""), ("Signed by", "30%"),
                                      ("Sealed (UTC)", "96px")], rows), unsafe_allow_html=True)
                st.caption("Each checkpoint names the one before it, so they form their own chain. A witness signs "
                           "a checkpoint only if it extends the ones it already signed.")
            else:
                st.info("No checkpoints yet. Select Seal now, or wait for the collector to seal (every few minutes).")
        with tab_chain:
            if ledger_records:
                cols = {"sequence_num": "#", "raw_hash": "Raw line hash", "record_hash": "Record hash",
                        "prev_hash": "Previous record hash", "timestamp": "Chained at"}
                df = pd.DataFrame(ledger_records)
                st.dataframe(df[[c for c in cols if c in df.columns]].rename(columns=cols), width="stretch",
                             hide_index=True, height=260)
            else:
                st.info("Nothing stored yet.")
