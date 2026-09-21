import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_simulate_real_device_traffic_endpoint():
    """Test POST /devices/simulate endpoint returns 5 real Suricata IDS events."""
    response = client.post("/devices/simulate")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert "Suricata" in data["device"]
    assert data["events_count"] == 5
    assert len(data["events"]) == 5

    first_evt = data["events"][0]
    assert "uuid" in first_evt
    assert "sha256" in first_evt
    assert "format" in first_evt
    assert "explanation" in first_evt
    assert "intent" in first_evt
