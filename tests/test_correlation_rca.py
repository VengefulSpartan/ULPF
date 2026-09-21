import pytest
from pathlib import Path
from backend.services.storage.db import Database
from backend.services.ingestion.pipeline import IngestionPipeline
from backend.services.correlation.engine import CorrelationEngine

@pytest.fixture
def rca_db(tmp_path):
    test_db_path = tmp_path / "test_rca.db"
    db_inst = Database(db_path=test_db_path)
    return db_inst

def test_cross_source_rca_correlation(rca_db, monkeypatch):
    import backend.services.storage.db as db_module
    import backend.services.ingestion.pipeline as pipe_module
    import backend.services.correlation.engine as corr_module
    import backend.services.integrity.ledger as ledger_module

    monkeypatch.setattr(db_module, "db", rca_db)
    monkeypatch.setattr(pipe_module, "db", rca_db)
    monkeypatch.setattr(corr_module, "db", rca_db)
    monkeypatch.setattr(ledger_module, "db", rca_db)

    # 1. Create sources
    with rca_db.get_connection() as conn:
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) VALUES ('src-vpn', 'FortiGate VPN', 'Fortinet', 'FortiGate', 'kv', 'vpn', datetime('now'))")
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) VALUES ('src-fw', 'Palo Alto FW', 'Palo Alto', 'PAN-OS', 'cef', 'firewall', datetime('now'))")
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) VALUES ('src-ids', 'Suricata IDS', 'Suricata', 'Suricata', 'json', 'ids', datetime('now'))")
        conn.commit()

    # 2. Ingest realistic multi-source sequence
    # Step 1: Fortinet VPN login
    vpn_log = 'date=2026-09-20 time=14:00:00 devname="FGT-VPN" type="vpn" action="login" status="success" user="contractor_bob" srcip=198.51.100.22 dstip=10.0.1.15'
    pipe_module.IngestionPipeline.ingest_single_log(vpn_log, "src-vpn", "Fortinet", "FortiGate")

    # Step 2: Palo Alto Firewall allowed connection
    fw_log = 'CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=allow'
    pipe_module.IngestionPipeline.ingest_single_log(fw_log, "src-fw", "Palo Alto", "PAN-OS")

    # Step 3: Suricata IDS Alert
    ids_log = '{"timestamp":"2026-09-20T14:00:45.000Z","src_ip":"10.0.1.15","dest_ip":"192.168.1.50","event_type":"alert","alert":{"action":"alerted","signature":"ET EXPLOIT EternalBlue SMB MS17-010","severity":"High"}}'
    pipe_module.IngestionPipeline.ingest_single_log(ids_log, "src-ids", "Suricata", "Suricata")

    # 3. Run Correlation
    incident = CorrelationEngine.run_correlation(pivot_ip="10.0.1.15")

    assert incident.title.startswith("Cross-Source Perimeter Incident")
    assert incident.confidence_score >= 0.70
    assert len(incident.observed_facts) == 3
    assert len(incident.inferred_relationships) >= 1

    # Check observed facts
    devices = [f.source_vendor for f in incident.observed_facts]
    assert "Fortinet" in devices
    assert "Palo Alto Networks" in devices or "Palo Alto" in devices

    # Check that inferred relationship clearly explains the hypothesis
    hypotheses = [r.hypothesis for r in incident.inferred_relationships]
    assert any("VPN" in h or "within" in h for h in hypotheses)
