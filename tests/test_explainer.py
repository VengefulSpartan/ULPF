import os
import glob
import pytest
from fastapi.testclient import TestClient

from core.detector.detector import FormatDetector
from core.explainer.explainer import SemanticExplainer, VALID_INTENTS
from api.main import app

client = TestClient(app)

SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "samples")
)


def test_explainer_on_all_samples():
    """Assert every sample format produces a non-empty explanation and valid intent tag."""
    explainer = SemanticExplainer()
    detector = FormatDetector()

    sample_files = glob.glob(os.path.join(SAMPLES_DIR, "*.log"))
    assert len(sample_files) >= 8, f"Expected at least 8 sample files, found {len(sample_files)}"

    total_tested = 0

    for filepath in sample_files:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            detection = detector.detect(line)

            # Construct mock OCSF event based on format detection
            mock_event = {
                "class_uid": 4001 if "cef" in detection.format else 3002 if "auth" in line.lower() else 1001,
                "class_name": "Network Activity",
                "activity_id": 1,
                "activity_name": "Log Event",
                "disposition": "BLOCK" if "block" in line.lower() or "deny" in line.lower() else "ALLOW",
                "src_endpoint": {"ip": "192.168.1.100", "port": 54321},
                "dst_endpoint": {"ip": "10.0.0.50", "port": 443},
                "user": {"name": "admin_user"},
                "process": {"name": "system_process"},
                "device": {"hostname": "firewall-01"}
            }

            res = explainer.explain_event(mock_event)
            explanation = res.get("explanation", "")
            intent = res.get("intent", "")

            assert isinstance(explanation, str)
            assert len(explanation) > 0, "Explanation must not be empty"
            assert intent in VALID_INTENTS, f"Invalid intent tag: {intent}"
            total_tested += 1

    assert total_tested >= 80, f"Expected >=80 log lines tested, got {total_tested}"


def test_explainer_fallback_template():
    """Assert unmapped (class_uid, activity_id) combinations never crash and produce non-empty fallback."""
    explainer = SemanticExplainer()

    unmapped_event = {
        "class_uid": 999999,
        "class_name": "Custom Unmapped Class",
        "activity_id": 8888,
        "activity_name": "Unknown Action",
        "disposition": "CUSTOM_DISP",
        "src_endpoint": {"ip": "172.16.0.99"}
    }

    res = explainer.explain_event(unmapped_event)
    assert "explanation" in res
    assert "intent" in res
    assert len(res["explanation"]) > 0
    assert res["intent"] in VALID_INTENTS


def test_explain_api_endpoint():
    """Test GET /events/{uuid}/explain HTTP endpoint."""
    response = client.get("/events/evt-001-firewall-block/explain")
    assert response.status_code == 200

    data = response.json()
    assert "raw_ref" in data
    assert "ocsf_event" in data
    assert "explanation" in data
    assert "intent" in data
    assert len(data["explanation"]) > 0
    assert data["intent"] in VALID_INTENTS


def test_rca_chained_narrative_endpoint():
    """Test GET /rca/{incident_id} includes chained_narrative."""
    response = client.get("/rca/inc-1001?window_seconds=300")
    assert response.status_code == 200

    data = response.json()
    assert "root_causes" in data
    assert len(data["root_causes"]) >= 1

    top_root = data["root_causes"][0]
    assert "chained_narrative" in top_root
    assert isinstance(top_root["chained_narrative"], str)
    assert len(top_root["chained_narrative"]) > 0
    assert "firewall" in top_root["chained_narrative"].lower() or "blocked" in top_root["chained_narrative"].lower()
