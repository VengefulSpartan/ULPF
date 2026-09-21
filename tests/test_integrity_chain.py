import pytest
import uuid
import json
from pathlib import Path
from backend.services.storage.db import Database
from backend.services.integrity.hasher import Hasher
from backend.services.integrity.ledger import IntegrityLedger

@pytest.fixture
def test_db(tmp_path):
    test_db_path = tmp_path / "test_ulpf.db"
    db_inst = Database(db_path=test_db_path)
    return db_inst

def test_canonical_json_determinism():
    dict1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
    dict2 = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
    # Keys in different orders must produce identical canonical string
    canon1 = Hasher.canonical_json(dict1)
    canon2 = Hasher.canonical_json(dict2)
    assert canon1 == canon2
    assert canon1 == '{"a":1,"b":2,"nested":{"x":10,"y":20}}'

def test_hash_chain_append_and_verify(test_db, monkeypatch):
    from backend.services.integrity import ledger as ledger_module
    monkeypatch.setattr(ledger_module, "db", test_db)

    # 1. Create a source
    with test_db.get_connection() as conn:
        conn.execute(
            "INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) "
            "VALUES ('src-1', 'Test Firewall', 'Cisco', 'ASA', 'syslog', 'firewall', datetime('now'))"
        )
        conn.commit()

    # 2. Append 5 sequential events
    with test_db.get_connection() as conn:
        cursor = conn.cursor()
        for i in range(1, 6):
            raw_id = f"raw-{i}"
            event_id = f"evt-{i}"
            raw_text = f"Sample raw log line {i}"
            raw_hash = Hasher.hash_raw_bytes(raw_text)

            cursor.execute(
                "INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected) "
                "VALUES (?, 'src-1', ?, ?, datetime('now'), 'syslog')",
                (raw_id, raw_text, raw_hash)
            )

            norm_data = {"event_num": i, "action": "allow", "src": f"10.0.0.{i}"}
            norm_json = json.dumps(norm_data)
            cursor.execute(
                """
                INSERT INTO normalized_events (
                    id, sequence_num, raw_id, class_uid, class_name, category_uid, category_name,
                    activity_id, activity_name, severity_id, severity, time, time_epoch_ms,
                    normalized_json, created_at
                ) VALUES (?, ?, ?, 4001, 'Network Activity', 4, 'Network Activity', 1, 'Traffic', 1, 'Info', '2026-09-20T00:00:00Z', 1000, ?, datetime('now'))
                """,
                (event_id, i, raw_id, norm_json)
            )

            IntegrityLedger.append_event(conn, event_id, raw_id, raw_hash, norm_data)
        conn.commit()

    # 3. Verify clean chain
    res = IntegrityLedger.verify_chain()
    assert res.is_valid is True
    assert res.total_records == 5
    assert res.verified_records == 5
    assert res.failed_records == 0
    assert len(res.issues) == 0

def test_tamper_detection_modified_payload(test_db, monkeypatch):
    from backend.services.integrity import ledger as ledger_module
    monkeypatch.setattr(ledger_module, "db", test_db)

    # Insert 3 events
    with test_db.get_connection() as conn:
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) VALUES ('src-1', 'FW', 'V', 'P', 'syslog', 'net', datetime('now'))")
        for i in range(1, 4):
            raw_id = f"r-{i}"
            event_id = f"e-{i}"
            raw_text = f"Raw text {i}"
            raw_hash = Hasher.hash_raw_bytes(raw_text)
            conn.execute("INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected) VALUES (?, 'src-1', ?, ?, datetime('now'), 'syslog')", (raw_id, raw_text, raw_hash))
            norm_data = {"seq": i, "action": "allow"}
            conn.execute("INSERT INTO normalized_events (id, sequence_num, raw_id, class_uid, class_name, category_uid, category_name, activity_id, activity_name, severity_id, severity, time, time_epoch_ms, normalized_json, created_at) VALUES (?, ?, ?, 4001, 'Net', 4, 'Net', 1, 'Traffic', 1, 'Info', '2026-09-20', 1, ?, datetime('now'))", (event_id, i, raw_id, json.dumps(norm_data)))
            IntegrityLedger.append_event(conn, event_id, raw_id, raw_hash, norm_data)
        conn.commit()

    # Tamper record #2 directly in database
    with test_db.get_connection() as conn:
        conn.execute("UPDATE normalized_events SET normalized_json = '{\"seq\":2,\"action\":\"TAMPERED_DROP\"}' WHERE sequence_num = 2")
        conn.commit()

    # Verify chain: should detect hash mismatch at record 2
    res = IntegrityLedger.verify_chain()
    assert res.is_valid is False
    assert res.failed_records >= 1
    assert res.first_corrupted_seq == 2
    assert any(i.issue_type == "HASH_MISMATCH" and i.sequence_num == 2 for i in res.issues)

def test_tamper_detection_deletion(test_db, monkeypatch):
    from backend.services.integrity import ledger as ledger_module
    monkeypatch.setattr(ledger_module, "db", test_db)

    # Insert 3 events
    with test_db.get_connection() as conn:
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, created_at) VALUES ('src-1', 'FW', 'V', 'P', 'syslog', 'net', datetime('now'))")
        for i in range(1, 4):
            raw_id = f"r-{i}"
            event_id = f"e-{i}"
            raw_text = f"Raw text {i}"
            raw_hash = Hasher.hash_raw_bytes(raw_text)
            conn.execute("INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected) VALUES (?, 'src-1', ?, ?, datetime('now'), 'syslog')", (raw_id, raw_text, raw_hash))
            norm_data = {"seq": i, "action": "allow"}
            conn.execute("INSERT INTO normalized_events (id, sequence_num, raw_id, class_uid, class_name, category_uid, category_name, activity_id, activity_name, severity_id, severity, time, time_epoch_ms, normalized_json, created_at) VALUES (?, ?, ?, 4001, 'Net', 4, 'Net', 1, 'Traffic', 1, 'Info', '2026-09-20', 1, ?, datetime('now'))", (event_id, i, raw_id, json.dumps(norm_data)))
            IntegrityLedger.append_event(conn, event_id, raw_id, raw_hash, norm_data)
        conn.commit()

    # Delete record #2 from ledger
    with test_db.get_connection() as conn:
        conn.execute("DELETE FROM integrity_ledger WHERE sequence_num = 2")
        conn.commit()

    # Verify: should detect sequence gap and broken chain pointer
    res = IntegrityLedger.verify_chain()
    assert res.is_valid is False
    assert any("SEQUENCE_GAP_OR_REORDER" in i.issue_type for i in res.issues)
