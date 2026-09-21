import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.storage.db import Database

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db_path = tmp_path / "test_api.db"
    db_inst = Database(db_path=test_db_path)
    
    import backend.services.storage.db as db_module
    import backend.api.sources as s_api
    import backend.api.ingestion as i_api
    import backend.api.parsers as p_api
    import backend.api.events as e_api
    import backend.api.integrity as int_api
    import backend.api.correlation as c_api
    import backend.api.analytics as a_api
    import backend.api.export as exp_api
    import backend.services.ingestion.pipeline as pipe_module
    import backend.services.integrity.ledger as l_module
    import backend.services.correlation.engine as ce_module

    monkeypatch.setattr(db_module, "db", db_inst)
    monkeypatch.setattr(s_api, "db", db_inst)
    monkeypatch.setattr(i_api, "db", db_inst)
    monkeypatch.setattr(p_api, "db", db_inst)
    monkeypatch.setattr(e_api, "db", db_inst)
    monkeypatch.setattr(int_api, "db", db_inst)
    monkeypatch.setattr(c_api, "db", db_inst)
    monkeypatch.setattr(a_api, "db", db_inst)
    monkeypatch.setattr(exp_api, "db", db_inst)
    monkeypatch.setattr(pipe_module, "db", db_inst)
    monkeypatch.setattr(l_module, "db", db_inst)
    monkeypatch.setattr(ce_module, "db", db_inst)

def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

def test_source_lifecycle():
    # 1. Create source
    src_data = {
        "name": "Test Palo Alto",
        "vendor": "Palo Alto Networks",
        "product": "PA-3200",
        "format_type": "cef",
        "category": "firewall"
    }
    create_resp = client.post("/api/sources", json=src_data)
    assert create_resp.status_code == 201
    source_id = create_resp.json()["id"]

    # 2. List sources
    list_resp = client.get("/api/sources")
    assert list_resp.status_code == 200
    assert any(s["id"] == source_id for s in list_resp.json())

def test_ingestion_and_integrity_api():
    # 1. Seed samples
    seed_resp = client.post("/api/ingest/seed-samples")
    assert seed_resp.status_code == 200
    assert seed_resp.json()["ingested_count"] >= 4

    # 2. Query events
    events_resp = client.get("/api/events")
    assert events_resp.status_code == 200
    events = events_resp.json()["events"]
    assert len(events) >= 4

    # 3. Verify integrity
    verify_resp = client.get("/api/integrity/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_valid"] is True
    assert verify_resp.json()["total_records"] >= 4

    # 4. Tamper record #2
    tamper_resp = client.post("/api/integrity/tamper", json={"sequence_num": 2, "tamper_field": "disposition", "new_value": "tampered_blocked"})
    assert tamper_resp.status_code == 200

    # 5. Verify integrity after tampering: must be invalid!
    reverify_resp = client.get("/api/integrity/verify")
    assert reverify_resp.status_code == 200
    assert reverify_resp.json()["is_valid"] is False
    assert reverify_resp.json()["first_corrupted_seq"] == 2

    # 6. Restore record
    restore_resp = client.post("/api/integrity/restore", json={"sequence_num": 2})
    assert restore_resp.status_code == 200

    # 7. Verify integrity again: must be valid!
    final_verify = client.get("/api/integrity/verify")
    assert final_verify.status_code == 200
    assert final_verify.json()["is_valid"] is True

def test_parser_generation_testing_and_approval_api():
    # 1. Generate candidate parser
    gen_req = {
        "name": "Test CEF Parser",
        "vendor": "Palo Alto",
        "product": "PAN-OS",
        "sample_logs": [
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.1 dst=10.0.1.2 act=allow"
        ]
    }
    gen_resp = client.post("/api/parsers/generate", json=gen_req)
    assert gen_resp.status_code == 201
    parser_id = gen_resp.json()["id"]
    assert gen_resp.json()["status"] == "candidate"

    # 2. Attempt approval before testing -> Must FAIL!
    approve_untested = client.post(f"/api/parsers/{parser_id}/approve")
    assert approve_untested.status_code == 400

    # 3. Test candidate parser
    test_req = {
        "sample_logs": [
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.1 dst=10.0.1.2 act=allow"
        ]
    }
    test_resp = client.post(f"/api/parsers/{parser_id}/test", json=test_req)
    assert test_resp.status_code == 200
    assert test_resp.json()["tested"] is True
    assert test_resp.json()["validation"]["accuracy_score"] == 100.0

    # 4. Now approve tested parser -> Must SUCCEED!
    approve_resp = client.post(f"/api/parsers/{parser_id}/approve")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"
