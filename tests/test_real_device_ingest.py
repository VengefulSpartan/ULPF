import pytest
from fastapi.testclient import TestClient

from core.detector.detector import FormatDetector
from core.explainer.explainer import SemanticExplainer, VALID_INTENTS
from api.main import app, ingest_pipeline
from scripts.real_device_traffic_gen import REAL_SURICATA_EVENTS

client = TestClient(app)


def test_real_suricata_log_detection():
    """Verify FormatDetector correctly identifies real Suricata IDS Syslog messages."""
    detector = FormatDetector()

    for event in REAL_SURICATA_EVENTS:
        raw_syslog = event["syslog"]
        res = detector.detect(raw_syslog)

        assert res.format in ["syslog_rfc3164", "syslog_rfc5424", "syslog_generic", "leef", "cef", "kv", "json"]
        assert res.confidence >= 0.5


def test_real_device_http_ingest():
    """Verify POST /ingest receives real Suricata IDS events and losslessly archives raw payload."""
    for event in REAL_SURICATA_EVENTS:
        raw_payload = event["syslog"].encode("utf-8")
        response = client.post(
            "/ingest",
            content=raw_payload,
            headers={"Content-Type": "application/octet-stream", "User-Agent": "Suricata-IDS/7.0"}
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "archived"
        assert "uuid" in data
        assert "sha256" in data
        assert len(data["sha256"]) == 64


def test_real_device_semantic_explanation():
    """Verify SemanticExplainer annotates real Suricata IDS alerts with plain English and valid intent."""
    explainer = SemanticExplainer()

    mock_suricata_ocsf = {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "activity_id": 1,
        "activity_name": "IDS Alert",
        "disposition": "ALERT",
        "src_endpoint": {"ip": "192.168.1.50", "port": 54321},
        "dst_endpoint": {"ip": "10.0.0.5", "port": 80}
    }

    res = explainer.explain_event(mock_suricata_ocsf)

    assert "explanation" in res
    assert "intent" in res
    assert res["intent"] in VALID_INTENTS
    assert len(res["explanation"]) > 0
    assert "192.168.1.50" in res["explanation"]
