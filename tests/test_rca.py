import os
import json
import pytest
from fastapi.testclient import TestClient

from rca.graph import TemporalEntityGraph
from rca.ranker import RCARanker
from api.main import app

client = TestClient(app)

SAMPLE_INCIDENT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "samples", "incident_synthetic.json")
)


def test_rca_engine_synthetic_incident():
    """Test RCA engine on multi-source incident dataset, asserting Firewall Block is ranked #1 root cause."""
    assert os.path.exists(SAMPLE_INCIDENT_PATH), f"Missing synthetic dataset at {SAMPLE_INCIDENT_PATH}"
    
    with open(SAMPLE_INCIDENT_PATH, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) == 4, "Expected 4 multi-source incident events"

    # Build Temporal Entity Graph
    graph_builder = TemporalEntityGraph(window_seconds=300.0)
    graph = graph_builder.build_graph(events)

    # Rank Root Causes
    ranker = RCARanker()
    candidates = ranker.rank_root_causes(graph)

    assert len(candidates) == 4, f"Expected 4 candidates, got {len(candidates)}"

    # Top root cause candidate MUST be Event 1 (Firewall Block)
    top_candidate = candidates[0]
    assert top_candidate["rank"] == 1
    assert top_candidate["event_uuid"] == "evt-001-firewall-block", (
        f"Expected top root cause 'evt-001-firewall-block', got '{top_candidate['event_uuid']}'"
    )

    # Verify score factors
    factors = top_candidate["factors"]
    assert factors["time_score"] == 1.0, f"Expected time_score 1.0 for earliest event, got {factors['time_score']}"
    assert factors["reachability_count"] >= 3, f"Expected reachability count >= 3, got {factors['reachability_count']}"

    # Verify causal chain
    causal_chain = top_candidate["causal_chain"]
    assert "evt-001-firewall-block" in causal_chain
    assert "evt-004-process-spawn" in causal_chain
    assert causal_chain.index("evt-001-firewall-block") < causal_chain.index("evt-004-process-spawn")


def test_get_rca_api_endpoint():
    """Test HTTP GET /rca/{incident_id} API endpoint."""
    response = client.get("/rca/inc-1001?window_seconds=300")
    assert response.status_code == 200

    data = response.json()
    assert data["incident_id"] == "inc-1001"
    assert data["total_events"] == 4
    assert len(data["root_causes"]) >= 1

    top_root_cause = data["root_causes"][0]
    assert top_root_cause["rank"] == 1
    assert top_root_cause["event_uuid"] == "evt-001-firewall-block"
    assert "causal_chain" in top_root_cause
