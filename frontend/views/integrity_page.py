import streamlit as st
import json
import pandas as pd
from frontend.api_client import APIClient

def render_integrity():
    st.markdown("## Integrity & Lineage (Chain-of-Custody)")
    st.caption("USP 2: Verifiable cryptographic hash-chaining, tamper detection, and raw-to-normalized lineage audit")

    st.markdown(
        """
        > **Evidence Standard Notice**: A successful cryptographic hash verification mathematically proves 
        > that log records have not been altered, reordered, or deleted since initial ingestion into ULPF. 
        > It is distinct from proof that the originating hardware appliance was truthful or completely collected.
        """
    )

    tab_audit, tab_demo, tab_ledger = st.tabs(["🔒 Chain Audit & Verification", "⚠️ Controlled Tampering Demo", "📜 Ledger Audit Records"])

    # 1. Verification Tab
    with tab_audit:
        col_btn, col_blank = st.columns([1, 2])
        with col_btn:
            run_audit = st.button("🔍 Run Full Chain Cryptographic Audit", type="primary", use_container_width=True)

        # Run verification
        res = APIClient.verify_integrity()
        is_valid = res.get("is_valid", True)
        total = res.get("total_records", 0)
        verified = res.get("verified_records", 0)
        failed = res.get("failed_records", 0)
        time_ms = res.get("verification_time_ms", 0.0)

        if is_valid:
            st.markdown(
                f"""
                <div style="background-color: #E8F5E9; border: 2px solid #2E7D32; border-radius: 6px; padding: 18px; margin: 15px 0;">
                    <div style="font-size: 1.25rem; font-weight: 700; color: #2E7D32;">✓ CHAIN INTEGRITY FULLY VERIFIED</div>
                    <div style="color: #1B5E20; margin-top: 4px;">
                        All {total} records in the cryptographic ledger match their SHA-256 preimages and hash pointers. 
                        Zero tampering, zero deletions, and zero reordering detected. Audit completed in {time_ms} ms.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div style="background-color: #FFEBEE; border: 2px solid #D32F2F; border-radius: 6px; padding: 18px; margin: 15px 0;">
                    <div style="font-size: 1.25rem; font-weight: 700; color: #D32F2F;">⚠️ INTEGRITY BREACH DETECTED</div>
                    <div style="color: #B71C1C; margin-top: 4px;">
                        Cryptographic ledger verification failed! First corrupted sequence: #{res.get('first_corrupted_seq')}. 
                        {failed} record(s) failed validation. Hash chain has been violated.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Metric cards
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Ledger Records Audited", total)
        m2.metric("Cryptographically Valid", verified)
        m3.metric("Integrity Failures", failed)
        m4.metric("Verification Duration", f"{time_ms} ms")

        # Display issues if any
        issues = res.get("issues", [])
        if issues:
            st.markdown("##### Detected Integrity Violations")
            for iss in issues:
                st.error(
                    f"**Sequence #{iss.get('sequence_num')}** — `{iss.get('issue_type')}`\n\n"
                    f"Description: {iss.get('description')}\n\n"
                    f"Expected Hash: `{iss.get('expected')}`\n\n"
                    f"Actual Hash: `{iss.get('actual')}`"
                )

    # 2. Tampering Demo Tab
    with tab_demo:
        st.markdown("##### Controlled Tampering Demonstration")
        st.write(
            "This interactive demo proves that any modification to a stored record—even a single bit in the SQLite database—"
            "instantly breaks the cryptographic hash chain and flags the exact record number."
        )

        ledger_records = APIClient.get_ledger(limit=50)
        if not ledger_records:
            st.warning("No ledger records available. Ingest sample logs first.")
            return

        seq_options = [r["sequence_num"] for r in ledger_records]
        col_sel, col_val = st.columns(2)
        with col_sel:
            target_seq = st.selectbox("Select Sequence Number to Tamper", seq_options)
        with col_val:
            tamper_val = st.text_input("New Malicious Value (for 'disposition')", value="UNAUTHORIZED_OVERRIDE_ALLOW")

        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("💥 Simulate Unauthorized Record Modification", type="primary"):
                tamper_res = APIClient.simulate_tamper(sequence_num=target_seq, value=tamper_val)
                if "error" in tamper_res:
                    st.error(tamper_res["error"])
                else:
                    st.warning(tamper_res.get("message"))
                    st.rerun()

        with col_act2:
            if st.button("🛡️ Restore Record to Legitimate State"):
                rest_res = APIClient.restore_record(sequence_num=target_seq)
                if "error" in rest_res:
                    st.error(rest_res["error"])
                else:
                    st.success(rest_res.get("message"))
                    st.rerun()

    # 3. Ledger Records Tab
    with tab_ledger:
        st.markdown("##### Cryptographic Hash Ledger")
        ledger_records = APIClient.get_ledger(limit=50)
        if ledger_records:
            df_ledger = pd.DataFrame(ledger_records)
            cols = ["sequence_num", "raw_hash", "record_hash", "prev_hash", "timestamp"]
            st.dataframe(df_ledger[[c for c in cols if c in df_ledger.columns]], use_container_width=True, hide_index=True)
        else:
            st.info("No records in ledger yet.")
