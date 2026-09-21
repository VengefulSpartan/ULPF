import streamlit as st
import json
import pandas as pd

def render_schema():
    st.markdown("## Schema Explorer")
    st.caption("OCSF (Open Cybersecurity Schema Framework) v1.1.0 Subset Specification")

    st.markdown(
        """
        ULPF normalizes heterogeneous perimeter telemetry into a standardized, analytics-ready OCSF v1.1.0 representation.
        Events map to three primary perimeter security classes:
        - **Class 4001**: Network Activity (Traffic flows, connections, ACL rules)
        - **Class 3002**: Authentication (VPN logons, user sessions, MFA verification)
        - **Class 2004**: Detection Finding (IDS/IPS signature alerts, exploit detections)
        """
    )

    tab_classes, tab_fields, tab_sample = st.tabs(["🏛️ OCSF Classes", "📋 Field Dictionary & Mappings", "📄 Schema Example"])

    with tab_classes:
        st.markdown("##### Standardized OCSF Classes")
        classes_data = [
            {"Class UID": 4001, "Class Name": "Network Activity", "Category UID": 4, "Category": "Network Activity", "Primary Appliances": "Palo Alto NGFW, Cisco ASA, pfSense, FortiOS"},
            {"Class UID": 3002, "Class Name": "Authentication", "Category UID": 3, "Category": "Identity & Access Management", "Primary Appliances": "FortiGate SSL-VPN, Cisco AnyConnect, RADIUS"},
            {"Class UID": 2004, "Class Name": "Detection Finding", "Category UID": 2, "Category": "Findings", "Primary Appliances": "Suricata IDS, Snort, Zeek, Threat Prevention"}
        ]
        st.dataframe(pd.DataFrame(classes_data), use_container_width=True, hide_index=True)

    with tab_fields:
        st.markdown("##### Standardized Attributes Dictionary")
        fields_data = [
            {"Field Name": "metadata.version", "Type": "string", "Required": "Yes", "Description": "OCSF Schema version ('1.1.0')"},
            {"Field Name": "metadata.raw_ref.raw_hash", "Type": "string (hex)", "Required": "Yes", "Description": "SHA-256 hash of the exact original raw log bytes"},
            {"Field Name": "metadata.sequence_num", "Type": "integer", "Required": "Yes", "Description": "Monotonically increasing sequence number in hash ledger"},
            {"Field Name": "class_uid", "Type": "integer", "Required": "Yes", "Description": "OCSF class identifier (e.g. 4001)"},
            {"Field Name": "severity_id", "Type": "integer", "Required": "Yes", "Description": "Normalized severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical"},
            {"Field Name": "time", "Type": "string (ISO 8601)", "Required": "Yes", "Description": "Event occurrence timestamp in UTC"},
            {"Field Name": "src_endpoint.ip", "Type": "string (IPv4/IPv6)", "Required": "Conditional", "Description": "Source IP address"},
            {"Field Name": "src_endpoint.port", "Type": "integer", "Required": "No", "Description": "Source port number (1-65535)"},
            {"Field Name": "dst_endpoint.ip", "Type": "string (IPv4/IPv6)", "Required": "Conditional", "Description": "Destination IP address"},
            {"Field Name": "dst_endpoint.port", "Type": "integer", "Required": "No", "Description": "Destination port number (1-65535)"},
            {"Field Name": "connection_info.protocol_name", "Type": "string", "Required": "No", "Description": "Transport protocol (TCP, UDP, ICMP)"},
            {"Field Name": "disposition", "Type": "string", "Required": "No", "Description": "Normalized action: 'allowed', 'denied', 'dropped', 'alert'"},
            {"Field Name": "user.name", "Type": "string", "Required": "No", "Description": "Identity or username associated with the event"},
            {"Field Name": "finding.title", "Type": "string", "Required": "No", "Description": "Signature or threat name for Detection Finding"},
            {"Field Name": "unmapped", "Type": "object (key-value)", "Required": "No", "Description": "Preserved vendor-specific fields outside schema"}
        ]
        st.dataframe(pd.DataFrame(fields_data), use_container_width=True, hide_index=True)

    with tab_sample:
        st.markdown("##### Example Canonical OCSF JSON Document")
        sample_doc = {
            "metadata": {
                "version": "1.1.0",
                "product": {"vendor_name": "Palo Alto Networks", "name": "PA-5200", "version": "10.1"},
                "sequence_num": 42,
                "raw_ref": {"raw_id": "c7a8b9-...", "raw_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            },
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "activity_id": 6,
            "activity_name": "Traffic",
            "type_uid": 400106,
            "severity_id": 3,
            "severity": "Medium",
            "time": "2026-09-20T14:00:32Z",
            "time_epoch_ms": 1789912832000,
            "src_endpoint": {"ip": "10.0.1.15", "port": 49152},
            "dst_endpoint": {"ip": "192.168.1.50", "port": 445},
            "connection_info": {"protocol_name": "TCP"},
            "disposition": "allowed",
            "action": "allow",
            "raw_data": "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=allow",
            "unmapped": {"deviceReceiptTime": "2026-09-20T14:00:32Z"}
        }
        st.json(sample_doc)
