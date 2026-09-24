"""
Correlation reports stored events and the rules that matched them, with the evidence each rule
used. These tests pin down that no confidence number appears anywhere, that each rule matches
only on the evidence it quotes, and that old incidents lose their made-up scores on upgrade.
"""
import json
import sqlite3

import pytest

from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.storage.db import Database

VPN_OK = ('date=2026-09-20 time=14:00:00 devname="FGT-VPN" type="vpn" action="login" status="success" '
          'user="contractor_bob" srcip=198.51.100.22 dstip=10.0.1.15')
VPN_FAIL = ('date=2026-09-20 time=14:00:00 devname="FGT-VPN" type="vpn" action="login" status="failure" '
            'user="contractor_bob" srcip=198.51.100.22 dstip=10.0.1.15')
FW_ALLOW = ('CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 '
            'proto=TCP act=allow deviceReceiptTime=2026-09-20T14:00:15Z')
IDS_ALERT = ('{"timestamp":"2026-09-20T14:00:45.000Z","src_ip":"10.0.1.15","dest_ip":"192.168.1.50",'
             '"event_type":"alert","alert":{"action":"alerted","signature":"ET EXPLOIT EternalBlue SMB MS17-010",'
             '"severity":1}}')


@pytest.fixture
def engine(isolated_db, monkeypatch):
    import backend.services.correlation.engine as corr_module
    monkeypatch.setattr(corr_module, "db", isolated_db)
    return corr_module.CorrelationEngine


def ingest(*lines_by_device):
    """(device address, line) pairs: each sending address registers as its own device."""
    StreamIngestor().ingest([InboundRecord(raw=line.encode(), transport="syslog-udp", input_name="test",
                                           peer_ip=peer) for peer, line in lines_by_device])


def kinds(incident):
    return sorted(l.relationship_type for l in incident.inferred_relationships)


def test_multi_device_sequence_is_linked_by_evidence_not_by_scores(engine):
    ingest(("192.0.2.1", VPN_OK), ("192.0.2.2", FW_ALLOW), ("192.0.2.3", IDS_ALERT))
    incident = engine.run_correlation(pivot_ip="10.0.1.15")

    assert len(incident.observed_facts) == 3 and len(incident.entities["devices"]) == 3
    assert kinds(incident) == ["ALLOWED_THEN_ALERT", "LOGIN_THEN_ACTIVITY"]
    login = next(l for l in incident.inferred_relationships if l.relationship_type == "LOGIN_THEN_ACTIVITY")
    assert login.shared_entities == ["10.0.1.15"] and login.time_delta_seconds == 15
    assert any("shared address 10.0.1.15" in e for e in login.evidence)
    alert = next(l for l in incident.inferred_relationships if l.relationship_type == "ALLOWED_THEN_ALERT")
    assert alert.shared_entities == ["10.0.1.15", "192.168.1.50"] and alert.time_delta_seconds == 30
    assert incident.severity == "High"  # the highest severity a device reported, not a computed guess
    assert "confidence" not in json.dumps(incident.model_dump()).lower()


def test_a_failed_login_links_nothing(engine):
    ingest(("192.0.2.1", VPN_FAIL), ("192.0.2.2", FW_ALLOW))
    assert "LOGIN_THEN_ACTIVITY" not in kinds(engine.run_correlation(pivot_ip="10.0.1.15"))


def test_an_alert_on_another_address_pair_is_not_linked(engine):
    other = IDS_ALERT.replace("192.168.1.50", "192.168.1.99")
    ingest(("192.0.2.2", FW_ALLOW), ("192.0.2.3", other))
    assert "ALLOWED_THEN_ALERT" not in kinds(engine.run_correlation(pivot_ip="10.0.1.15"))


@pytest.mark.parametrize("ports, expected", [(10, ["PORT_SWEEP"]), (9, [])])
def test_port_sweep_needs_the_stated_number_of_ports(engine, ports, expected):
    lines = [("192.0.2.2", f"CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=203.0.113.66 dst=10.0.0.5 "
                           f"spt=40000 dpt={1000 + i} proto=TCP act=deny deviceReceiptTime=2026-09-20T14:00:{i:02d}Z")
             for i in range(ports)]
    ingest(*lines)
    incident = engine.run_correlation(pivot_ip="203.0.113.66")
    assert kinds(incident) == expected
    if expected:
        assert incident.inferred_relationships[0].evidence[0].startswith(f"{ports} distinct destination ports")


def test_nothing_found_says_so(engine):
    incident = engine.run_correlation(pivot_ip="10.9.9.9")
    assert incident.observed_facts == [] and "No events found" in incident.title


def test_old_incidents_lose_their_made_up_scores_on_upgrade(tmp_path):
    path = tmp_path / "old.db"
    old = {"incident_id": "i1", "title": "t", "severity": "High", "confidence_score": 0.89,
           "inferred_relationships": [{"relationship_type": "RECON_TO_EXPLOIT", "confidence": 0.92}]}
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, "
                 "confidence_score REAL NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, "
                 "data_json TEXT NOT NULL, created_at TEXT NOT NULL)")
    conn.execute("INSERT INTO incidents VALUES ('i1', 't', 'High', 0.89, 'a', 'b', ?, 'c')", (json.dumps(old),))
    conn.commit()
    conn.close()

    database = Database(db_path=path)
    with database.get_connection() as c:
        columns = {r[1] for r in c.execute("PRAGMA table_info(incidents)")}
        stored = json.loads(c.execute("SELECT data_json FROM incidents").fetchone()[0])
    assert "confidence_score" not in columns
    assert "confidence" not in json.dumps(stored)
    assert stored["inferred_relationships"][0]["relationship_type"] == "RECON_TO_EXPLOIT"
