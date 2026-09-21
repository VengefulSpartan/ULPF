import streamlit as st
import json
import pandas as pd
from frontend.api_client import APIClient

def render_parser_studio():
    st.markdown("## Parser Studio (Zero-Touch Parser Generation)")
    st.caption("USP 1: Autonomous parser inference, candidate generation, multi-sample validation, and approval workflow")

    tab_gen, tab_list = st.tabs(["⚡ Generate & Test Candidate Parser", "📂 Parser Registry & Approval"])

    # 1. Generate & Test Tab
    with tab_gen:
        st.markdown("##### 1. Specify Appliance & Raw Log Samples")
        c1, c2, c3 = st.columns(3)
        with c1:
            p_name = st.text_input("Parser Name", value="PAN-OS Threat & Traffic Parser")
        with c2:
            p_vendor = st.text_input("Device Vendor", value="Palo Alto Networks")
        with c3:
            p_product = st.text_input("Product Model", value="PA-5200")

        default_samples = (
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=allow\n"
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|vulnerability|5|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=drop threat_name=\"SMB Remote Code Execution\"\n"
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|end|2|src=192.168.1.10 dst=8.8.8.8 spt=53000 dpt=53 proto=UDP act=allow bytes_sent=64 bytes_received=128"
        )
        sample_text = st.text_area("Sample Raw Log Lines (1 to N lines)", value=default_samples, height=130)

        if st.button("🔮 Generate Candidate Parser", type="primary"):
            lines = [l.strip() for l in sample_text.splitlines() if l.strip()]
            if not lines:
                st.error("Please provide at least one sample line.")
            else:
                with st.spinner("Analyzing log format envelope and extracting tokens..."):
                    res = APIClient.generate_parser(
                        name=p_name,
                        vendor=p_vendor,
                        product=p_product,
                        sample_logs=lines
                    )
                    st.session_state["active_candidate"] = res
                    st.success(f"✓ Candidate parser generated: {res.get('id')}")

        # If a candidate is active, display rules and test actions
        active = st.session_state.get("active_candidate")
        if active:
            st.markdown("---")
            st.markdown("##### 2. Candidate Rule & OCSF Mapping Review")
            col_meta1, col_meta2, col_meta3 = st.columns(3)
            with col_meta1:
                st.markdown(f"**Parser ID**: `{active.get('id')}`")
                st.markdown(f"**Format Detected**: `{active.get('format_type')}`")
            with col_meta2:
                status_color = "warning" if active.get("status") == "candidate" else "success"
                st.markdown(f"**Status**: <span class='badge badge-{status_color}'>{active.get('status').upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"**Tested**: {'✓ Yes' if active.get('tested') else '✗ Untested'}")
            with col_meta3:
                st.markdown(f"**Target OCSF Class**: `{active.get('target_ocsf_class')}` (Network Activity)")

            # Mappings Table
            rule = active.get("rule", {})
            mappings = rule.get("mappings", [])
            if mappings:
                st.markdown("**Inferred Field Mappings:**")
                df_map = pd.DataFrame(mappings)
                st.dataframe(df_map, use_container_width=True, hide_index=True)

            st.markdown("##### 3. Candidate Validation Suite")
            st.info("⚠️ **Strict Approval Policy**: Untested parsers cannot be approved. Run validation against samples to verify parsing accuracy.")
            
            lines = [l.strip() for l in sample_text.splitlines() if l.strip()]
            col_t1, col_t2, col_t3 = st.columns([2, 1, 1])
            with col_t1:
                if st.button("🧪 Run Validation Test Suite", use_container_width=True):
                    with st.spinner("Testing candidate against sample batch..."):
                        tested_res = APIClient.test_parser(active.get("id"), lines)
                        st.session_state["active_candidate"] = tested_res
                        st.rerun()

            val = active.get("validation")
            if val:
                st.markdown("###### Test Results:")
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Total Tested", val.get("total_samples", 0))
                r2.metric("Passed", val.get("passed_samples", 0))
                r3.metric("Failed", val.get("failed_samples", 0))
                r4.metric("Accuracy Score", f"{val.get('accuracy_score', 0)}%")

                unmapped = val.get("unmapped_fields", [])
                if unmapped:
                    st.warning(f"Unmapped Fields Detected: {', '.join(unmapped)}")

                # Sample inspection
                with st.expander("Inspect Extracted Sample Results"):
                    for idx, sample_res in enumerate(val.get("sample_results", [])):
                        st.markdown(f"**Sample {idx + 1}**: `{'✓ Passed' if sample_res.get('passed') else '✗ Failed'}`")
                        st.code(sample_res.get("sample_log"), language="text")
                        if sample_res.get("extracted_fields"):
                            st.json(sample_res.get("extracted_fields"))

            # Approval buttons
            st.markdown("##### 4. Governance & Approval Gate")
            col_app, col_rej, col_sp = st.columns([1, 1, 2])
            with col_app:
                if st.button("✅ Approve Parser", type="primary", use_container_width=True):
                    res_app = APIClient.approve_parser(active.get("id"))
                    if "error" in res_app:
                        st.error(f"Approval Blocked: {res_app['error']}")
                    else:
                        st.success("✓ Candidate approved and promoted to active parsing registry!")
                        st.session_state["active_candidate"] = res_app
                        st.rerun()
            with col_rej:
                if st.button("❌ Reject Parser", use_container_width=True):
                    res_rej = APIClient.reject_parser(active.get("id"))
                    st.warning("Candidate parser rejected.")
                    st.session_state["active_candidate"] = res_rej
                    st.rerun()

    # 2. Registry Tab
    with tab_list:
        st.markdown("##### Parser Registry")
        parsers = APIClient.list_parsers()
        if parsers:
            for p in parsers:
                status_badge = "success" if p.get("status") == "approved" else ("error" if p.get("status") == "rejected" else "warning")
                with st.expander(f"{p.get('name')} — [{p.get('vendor')} {p.get('product')}] — {p.get('status').upper()}"):
                    st.markdown(f"**Status**: <span class='badge badge-{status_badge}'>{p.get('status').upper()}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Description**: {p.get('description')}")
                    st.markdown(f"**Format**: `{p.get('format_type')}` | **Target Class**: `{p.get('target_ocsf_class')}`")
                    st.markdown(f"**Approved By**: {p.get('approved_by') or 'Pending Review'} at {p.get('approved_at') or 'N/A'}")
                    st.markdown("**Rule Specification:**")
                    st.json(p.get("rule", {}))
        else:
            st.info("No parsers in registry. Generate one in the tab above.")
