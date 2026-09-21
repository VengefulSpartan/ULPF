import pytest
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer

def test_ocsf_normalization_network():
    parsed = {
        "src": "192.168.1.100",
        "spt": "50000",
        "dst": "10.0.0.1",
        "dpt": "443",
        "proto": "TCP",
        "act": "allow",
        "severity_raw": "3",
        "timestamp": "2026-09-20T12:00:00Z",
        "vendor": "Palo Alto Networks",
        "product": "PA-5200",
        "custom_rule_id": "RULE-999"
    }
    raw_text = "sample raw log line"
    event = OCSFNormalizer.normalize(
        parsed_data=parsed,
        raw_text=raw_text,
        raw_id="test-raw-1",
        raw_hash="hash123",
        vendor="Palo Alto",
        product="PA-5200"
    )

    assert event.class_uid == 4001
    assert event.class_name == "Network Activity"
    assert event.src_endpoint.ip == "192.168.1.100"
    assert event.src_endpoint.port == 50000
    assert event.dst_endpoint.ip == "10.0.0.1"
    assert event.dst_endpoint.port == 443
    assert event.connection_info.protocol_name == "TCP"
    assert event.disposition == "allowed"
    assert event.severity_id == 3 # 3 on 1-5 scale maps to Medium
    assert event.severity == "Medium"
    assert event.raw_data == raw_text
    assert event.metadata.raw_ref.raw_hash == "hash123"
    assert "custom_rule_id" in event.unmapped

def test_ocsf_normalization_auth():
    parsed = {
        "user": "admin_alice",
        "src": "172.16.0.45",
        "status": "success",
        "vpn": "SSL-VPN"
    }
    event = OCSFNormalizer.normalize(
        parsed_data=parsed,
        raw_text="User admin_alice logged into SSL-VPN",
        raw_id="raw-2",
        raw_hash="hash456",
        vendor="Fortinet",
        product="FortiGate"
    )

    assert event.class_uid == 3001
    assert event.class_name == "Authentication"
    assert event.user.name == "admin_alice"
    assert event.status == "success"

def test_ocsf_normalization_finding():
    parsed = {
        "src": "10.1.1.1",
        "dst": "10.1.1.2",
        "signature": "ET SCAN Nmap Scripting Engine",
        "severity": "High"
    }
    event = OCSFNormalizer.normalize(
        parsed_data=parsed,
        raw_text="ET SCAN Nmap alert detected",
        raw_id="raw-3",
        raw_hash="hash789",
        vendor="Suricata",
        product="Suricata IDS"
    )

    assert event.class_uid == 2001
    assert event.class_name == "Security Finding"
    assert event.finding.title == "ET SCAN Nmap Scripting Engine"
    assert event.severity_id == 4
    assert event.severity == "High"
