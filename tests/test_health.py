import pytest
from fastapi.testclient import TestClient
from api.main import app, check_opensearch, check_minio, check_redpanda

client = TestClient(app)


def test_health_check_endpoint():
    """Verify that GET /health returns proper status structure."""
    response = client.get("/health")
    assert response.status_code in (200, 503)
    
    data = response.json()
    assert "status" in data
    assert "services" in data
    assert "opensearch" in data["services"]
    assert "minio" in data["services"]
    assert "redpanda" in data["services"]
    assert isinstance(data["services"]["opensearch"], bool)
    assert isinstance(data["services"]["minio"], bool)
    assert isinstance(data["services"]["redpanda"], bool)


def test_health_check_service_functions():
    """Verify health check functions return boolean values."""
    assert isinstance(check_opensearch(), bool)
    assert isinstance(check_minio(), bool)
    assert isinstance(check_redpanda(), bool)
