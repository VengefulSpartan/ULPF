import pandas as pd
import streamlit as st

from backend.services.normalization.ocsf_export import OCSF_VERSION
from frontend import ui

CLASSES = [
    {"Class": 4001, "Name": "Network Activity", "Category": "Network Activity",
     "Typical sources": "Palo Alto, Cisco ASA, pfSense, FortiGate traffic logs"},
    {"Class": 3002, "Name": "Authentication", "Category": "Identity & Access Management",
     "Typical sources": "FortiGate SSL-VPN, Cisco AnyConnect, RADIUS"},
    {"Class": 2004, "Name": "Detection Finding", "Category": "Findings",
     "Typical sources": "Suricata, Snort, firewall IPS, the TRACELOG baseline detector"},
    {"Class": 0, "Name": "Base Event", "Category": "Uncategorized",
     "Typical sources": "Lines no parser could classify (kept, chained and forwarded)"},
]
FIELDS = [
    ("class_uid, class_name", "integer, string", "Yes", "OCSF class, for example 4001 Network Activity"),
    ("type_uid", "integer", "Yes", "class_uid × 100 + activity_id"),
    ("severity_id, severity", "integer, string", "Yes", "1 informational, 2 low, 3 medium, 4 high, 5 critical"),
    ("time", "integer (epoch ms)", "Yes", "When the event happened, UTC"),
    ("metadata.version", "string", "Yes", f"OCSF version ('{OCSF_VERSION}')"),
    ("metadata.uid", "string", "Yes", "The event's ID in TRACELOG"),
    ("metadata.sequence", "integer", "Yes", "Position in the integrity chain"),
    ("metadata.labels", "strings", "Yes", "tracelog.raw_sha256: SHA-256 of the raw bytes; tracelog.raw_id: the archived line"),
    ("metadata.product", "object", "Yes", "Vendor and product of the device that sent the line"),
    ("src_endpoint.ip, .port", "string, integer", "Network Activity", "Source address and port"),
    ("dst_endpoint.ip, .port", "string, integer", "Network Activity", "Destination address and port"),
    ("connection_info.protocol_name", "string", "No", "tcp, udp, icmp"),
    ("action, disposition", "string", "No", "Allowed, Denied, Dropped, Alert (with their _id)"),
    ("user.name", "string", "Authentication", "User or account"),
    ("finding_info.title, .uid", "string", "Detection Finding", "Signature or threat name"),
    ("observables", "array", "No", "Addresses and users, for SIEM search"),
    ("raw_data", "string", "No", "The original line"),
    ("unmapped", "object", "No", "Vendor fields with no OCSF equivalent, kept as they came"),
]


def render_schema():
    ui.page_header("Schema", f"OCSF {OCSF_VERSION}: the classes and fields TRACELOG writes")

    tab_classes, tab_fields, tab_sample = st.tabs(["Classes", "Fields", "Example"])
    with tab_classes:
        st.dataframe(pd.DataFrame(CLASSES), width="stretch", hide_index=True)
        with st.expander(f"Why OCSF {OCSF_VERSION} and not the newest release?"):
            st.markdown(
                f"""
                OCSF is past 1.9. TRACELOG writes **{OCSF_VERSION}** on purpose.

                - **Amazon Security Lake reads OCSF 1.3 and earlier** for custom sources. It is the strictest
                  consumer we send to, so it sets the ceiling. The Parquet output refuses to write anything newer
                  instead of filling a bucket the lake will not read.
                - **SIEMs are not strict.** Splunk, Elastic, Sentinel, QRadar, Wazuh and Loki map the fields
                  themselves, and none of them refuse an event for being 1.1 rather than 1.9.
                - **The attributes our classes require did not change between 1.1 and 1.3**, so moving within that
                  range is a setting (`OCSF_VERSION`), not a rewrite. The tests check that events still validate
                  at 1.2 and 1.3.

                The decision and what a newer schema would take are in `docs/adr/0001-ocsf-version.md`.
                """
            )

    with tab_fields:
        st.dataframe(pd.DataFrame(FIELDS, columns=["Field", "Type", "Required", "Meaning"]), width="stretch",
                     hide_index=True)

    with tab_sample:
        from backend.services.normalization.ocsf_export import to_ocsf, validate
        from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
        from backend.services.parsing.dispatch import parse_log
        raw = ("CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 "
               "dpt=445 proto=TCP act=allow rt=Sep 20 2026 14:00:32")
        st.caption("This raw line, normalized now by the same code the pipeline runs:")
        st.code(raw, language="text", wrap_lines=True)
        _, parsed = parse_log(raw)
        ev = OCSFNormalizer.normalize(parsed, raw, "example", "example", vendor=parsed.get("vendor") or "Generic",
                                      product=parsed.get("product") or "Device", sequence_num=42)
        sample_doc = to_ocsf(ev.model_dump())
        problems = validate(sample_doc)
        st.caption("It passes the OCSF 1.1.0 checks every output applies." if not problems else
                   "OCSF check: " + "; ".join(problems))
        st.json(sample_doc)
