import os
import uuid
import tempfile
import asyncio
import pytest
from fastapi.testclient import TestClient

from ingest.models import RawEvent, HashChainBlock
from storage.archive import RawArchiveManager, HashChainLedger
from ingest.ingester import IngestPipeline
from ingest.syslog import parse_syslog_metadata, SyslogUDPProtocol
from ingest.file_tailer import FileTailer
from api.main import app

client = TestClient(app)


def test_byte_for_byte_round_trip():
    """Requirement (a): Prove byte-for-byte round trip of raw payload."""
    archive_mgr = RawArchiveManager()
    
    # Test payloads: plain text, binary, complex utf-8 bytes
    test_payloads = [
        b"Jan 12 10:00:00 myhost myapp[1234]: User admin logged in from 192.168.1.50",
        bytes([0x00, 0xFF, 0xFE, 0xFD, 0x80, 0x90, 0xAB, 0xCD]),
        "CEF:0|Vendor|Product|1.0|100|Login Failed|5|src=10.0.0.1 msg=Test £€\U0001F600".encode("utf-8")
    ]

    for raw_bytes in test_payloads:
        date_str = "2026-09-15"
        event_uuid = str(uuid.uuid4())
        
        # Archive payload
        object_path = archive_mgr.archive_raw(date_str, event_uuid, raw_bytes)
        
        # Retrieve payload byte-for-byte
        retrieved_bytes = archive_mgr.retrieve_raw(object_path)
        
        assert retrieved_bytes == raw_bytes, f"Byte-for-byte mismatch! Expected {raw_bytes!r}, got {retrieved_bytes!r}"


def test_hash_chain_tamper_detection():
    """Requirement (b): Prove hash chain breaks if an archived record or ledger block is modified."""
    ledger = HashChainLedger()

    # Appending 3 events
    b1 = ledger.append("uuid-1", "sha256-hash-1")
    b2 = ledger.append("uuid-2", "sha256-hash-2")
    b3 = ledger.append("uuid-3", "sha256-hash-3")

    # Verify initially intact
    is_valid, tampered_seq = ledger.verify_integrity()
    assert is_valid is True
    assert tampered_seq is None

    # Case 1: Modify payload sha256 hash in middle block (sequence 2)
    original_sha256 = ledger.blocks[1].sha256
    ledger.blocks[1].sha256 = "tampered-sha256-hash-2"

    is_valid_tampered, tampered_seq = ledger.verify_integrity()
    assert is_valid_tampered is False
    assert tampered_seq == 2

    # Restore block 2 sha256
    ledger.blocks[1].sha256 = original_sha256
    is_valid_restored, _ = ledger.verify_integrity()
    assert is_valid_restored is True

    # Case 2: Modify block_hash directly in block 3
    ledger.blocks[2].block_hash = "fake_block_hash"
    is_valid_block_tampered, tampered_seq_3 = ledger.verify_integrity()
    assert is_valid_block_tampered is False
    assert tampered_seq_3 == 3


def test_syslog_metadata_parsers():
    """Test RFC3164 and RFC5424 Syslog metadata parsing."""
    # RFC3164 sample
    rfc3164_raw = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    meta3164 = parse_syslog_metadata(rfc3164_raw)
    assert meta3164["format"] == "rfc3164"
    assert meta3164["prival"] == 34
    assert meta3164["facility"] == 4  # 34 >> 3 = 4 (auth)
    assert meta3164["severity"] == 2  # 34 & 7 = 2 (crit)
    assert meta3164["hostname"] == "mymachine"

    # RFC5424 sample
    rfc5424_raw = b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1011 ID47 [exampleSDID@32473 iut="3"] An application event log entry'
    meta5424 = parse_syslog_metadata(rfc5424_raw)
    assert meta5424["format"] == "rfc5424"
    assert meta5424["prival"] == 165
    assert meta5424["facility"] == 20
    assert meta5424["severity"] == 5
    assert meta5424["app_name"] == "evntslog"
    assert meta5424["proc_id"] == "1011"


@pytest.mark.asyncio
async def test_file_tailer_ingestion():
    """Test file tailer reading lines and feeding into IngestPipeline."""
    ledger = HashChainLedger()
    archive_mgr = RawArchiveManager()
    pipeline = IngestPipeline(archive_manager=archive_mgr, ledger=ledger)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp_file:
        tmp_path = tmp_file.name

    try:
        tailer = FileTailer(tmp_path, pipeline, poll_interval=0.1)
        tailer.start()

        await asyncio.sleep(0.1)

        # Write lines to temp file
        line1 = b"2026-09-15 18:00:00 INFO Service started\n"
        line2 = b"2026-09-15 18:00:05 ERROR Connection reset by peer\n"

        with open(tmp_path, "ab") as f:
            f.write(line1)
            f.flush()
            await asyncio.sleep(0.3)
            f.write(line2)
            f.flush()
            await asyncio.sleep(0.3)

        await tailer.stop()

        # Check ledger entries ingested
        assert len(ledger.blocks) == 2
        is_valid, _ = ledger.verify_integrity()
        assert is_valid is True

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_post_ingest_api_endpoint():
    """Test HTTP POST /ingest API endpoint."""
    raw_payload = b"CEF:0|CheckPoint|FW1|6.0|Log|Accept|0|act=Accept src=192.168.1.1 dst=10.0.0.1"
    response = client.post(
        "/ingest",
        content=raw_payload,
        headers={"Content-Type": "application/octet-stream"}
    )
    assert response.status_code == 201
    
    data = response.json()
    assert data["status"] == "archived"
    assert "uuid" in data
    assert "sha256" in data
    assert "receipt_ts" in data
