import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_get_live_stats_endpoint():
    """Test GET /stats/live API route."""
    response = client.get("/stats/live")
    assert response.status_code == 200
    
    data = response.json()
    assert data["ingestion_status"] == "active"
    assert "throughput_eps" in data
    assert "events_processed" in data
    assert "raw_storage_bytes" in data
    assert "hash_chain_valid" in data
    assert "format_breakdown" in data
    assert isinstance(data["format_breakdown"], dict)
    assert data["format_breakdown"]["cef"] >= 1


def test_get_draft_plugins_endpoint():
    """Test GET /plugins/drafts API route."""
    response = client.get("/plugins/drafts")
    assert response.status_code == 200
    
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    
    draft = data[0]
    assert "parser_id" in draft
    assert "detected_format" in draft
    assert "template_mined" in draft
    assert "field_mappings" in draft
    assert isinstance(draft["field_mappings"], list)
