"""
PS 26156, expected solution (a): "Preserve complete raw event data without information loss."

What that means here is stated in docs/adr/0002-raw-preservation.md, and these tests hold each part
of it on every path a line can arrive by — a stream, the API, a file upload:

  - the bytes of the line are stored exactly, whatever they are;
  - the one line terminator the transport added is recorded, so the bytes as received can be rebuilt;
  - raw_hash is SHA-256 of the bytes received, so it proves what the device sent;
  - rows written before this rule still verify, and tampering with stored bytes is still caught.

Each case here was a defect found by probing the build on 24 September: uploads replaced invalid
bytes with U+FFFD, the API stripped whitespace, and a non-UTF-8 line's hash was of its re-encoding.
"""
import hashlib

import pytest
from fastapi.testclient import TestClient

from backend.services.ingestion.pipeline import IngestionPipeline, split_upload
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.integrity.hasher import Hasher
from backend.services.integrity.ledger import IntegrityLedger

TERMINATORS = {b"": "", b"\n": "LF", b"\r\n": "CRLF"}

LINES = {
    "utf-8": b"<14>Sep 20 14:00:15 fw1 app: user=alice action=allow",
    "latin-1 byte": b"<14>Sep 20 14:00:15 fw1 app: user=J\xf6rg action=deny",
    "invalid utf-8": b"<14>Sep 20 14:00:15 fw1 app: blob=\xff\xfe\x80 end",
    "padded": b"   <14>Sep 20 14:00:15 fw1 app: padded line \t ",
    "multibyte utf-8": "<14>Sep 20 14:00:15 fw1 app: city=Bhubaneswar ଭୁବନେଶ୍ୱର".encode(),
    "trailing CR kept": b"<14>Sep 20 14:00:15 fw1 app: ends with a lone CR\r",
}


def stored(db, raw_id):
    with db.get_connection() as conn:
        return conn.execute("SELECT raw_text, raw_encoding, raw_hash, raw_hash_of, raw_framing, transport "
                            "FROM raw_logs WHERE id = ?", (raw_id,)).fetchone()


def source(db, name="lossless"):
    with db.get_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO sources (id, name, vendor, product, format_type, category, is_active, "
                     "created_at, event_count) VALUES (?, ?, 'Generic', 'Device', 'syslog', 'network', 1, "
                     "datetime('now'), 0)", (name, name))
        conn.commit()
    return name


FRAMING_BYTES = {"": b"", "LF": b"\n", "CRLF": b"\r\n"}


def assert_exact(row, received: bytes):
    """The guarantee, stated independently of how it is implemented."""
    line = row["raw_text"].encode(row["raw_encoding"])
    terminator = FRAMING_BYTES[row["raw_framing"] or ""]
    assert line + terminator == received, "the bytes as received must be rebuildable, exactly"
    assert row["raw_hash"] == hashlib.sha256(line).hexdigest(), "the hash must be of the bytes received"
    assert row["raw_hash_of"] == "bytes"


def documented_framing(received: bytes) -> str:
    """ADR 0002: exactly one terminator is framing, CRLF before LF. A line that itself ends in CR,
    sent with an LF after it, is indistinguishable from CRLF on the wire — and rebuilds identically."""
    return "CRLF" if received.endswith(b"\r\n") else "LF" if received.endswith(b"\n") else ""


@pytest.mark.parametrize("name", list(LINES))
@pytest.mark.parametrize("terminator", list(TERMINATORS))
def test_a_streamed_line_is_kept_exactly_and_hashed_as_received(isolated_db, name, terminator):
    received = LINES[name] + terminator
    ev = StreamIngestor().ingest([InboundRecord(raw=received, transport="syslog-udp", input_name="t")])[0]
    row = stored(isolated_db, ev.raw_id)
    assert_exact(row, received)
    assert row["raw_framing"] == documented_framing(received)


def test_an_uploaded_file_keeps_every_byte_of_every_line(isolated_db):
    content = (LINES["latin-1 byte"] + b"\r\n" + LINES["invalid utf-8"] + b"\n" + b"#Fields: date time c-ip\n"
               + LINES["padded"] + b"\r\n" + LINES["utf-8"])            # the last line has no terminator
    lines = split_upload(content)
    assert b"".join(lines) == content, "splitting must not lose a byte"

    result = IngestionPipeline.ingest_batch(lines, source(isolated_db), transport="upload")
    assert result["ingested"] == 5                                       # the '#Fields' header is kept too
    with isolated_db.get_connection() as conn:
        rows = conn.execute("SELECT raw_text, raw_encoding, raw_framing FROM raw_logs "
                            "WHERE transport = 'upload' ORDER BY rowid").fetchall()
    rebuilt = b"".join(r["raw_text"].encode(r["raw_encoding"]) + FRAMING_BYTES[r["raw_framing"]] for r in rows)
    assert rebuilt == content, "the file must be rebuildable, byte for byte, from what was stored"
    assert not any("�" in r["raw_text"] for r in rows), "no byte may be replaced"


def test_the_upload_endpoint_does_not_replace_bytes(isolated_db):
    from backend.main import app
    src = source(isolated_db, "upload-endpoint")
    body = b"line one caf\xe9 end\r\nline two\n"
    r = TestClient(app).post("/api/ingest/file", files={"file": ("x.log", body)}, data={"source_id": src})
    assert r.status_code == 200 and r.json()["ingested"] == 2
    with isolated_db.get_connection() as conn:
        row = conn.execute("SELECT raw_text, raw_encoding, raw_hash FROM raw_logs "
                           "WHERE raw_text LIKE 'line one%'").fetchone()
    assert row["raw_text"].encode(row["raw_encoding"]) == b"line one caf\xe9 end"
    assert row["raw_hash"] == hashlib.sha256(b"line one caf\xe9 end").hexdigest()


def test_a_line_sent_to_the_api_keeps_its_whitespace(isolated_db):
    line = "   <14>Sep 20 14:00:15 fw1 app: spaced out \t  "
    res = IngestionPipeline.ingest_single_log(line, source(isolated_db))
    row = stored(isolated_db, res["raw_id"])
    assert row["raw_text"] == line and row["transport"] == "api"
    assert res["raw_hash"] == row["raw_hash"] == hashlib.sha256(line.encode()).hexdigest()


def test_blank_lines_are_not_events_but_everything_else_is(isolated_db):
    res = IngestionPipeline.ingest_batch(["", "   ", "# a comment the device wrote", "real line"],
                                         source(isolated_db))
    assert res["ingested"] == 2 and res["skipped_blank"] == 2


def test_a_line_whose_parser_raises_is_still_archived_hashed_and_chained(isolated_db, monkeypatch):
    import backend.services.ingestion.stream as stream

    def broken(*_args, **_kwargs):
        raise RuntimeError("a parser bug")

    monkeypatch.setattr(stream, "parse_log", broken)
    raw = b"<14>Sep 20 14:00:15 fw1 app: src=10.0.0.1 dst=10.0.0.2"
    stored = StreamIngestor().ingest([InboundRecord(raw=raw, transport="syslog-udp", input_name="t")])
    assert len(stored) == 1
    assert stored[0].normalized["class_uid"] == 0 and "a parser bug" in str(stored[0].normalized["unmapped"])
    assert stored[0].raw_hash == hashlib.sha256(raw).hexdigest()
    assert IntegrityLedger.verify_chain().is_valid


def test_rows_written_before_the_rule_still_verify_and_tampering_is_still_caught(isolated_db):
    """A chain spanning both rules verifies; changing one stored byte breaks it either way."""
    StreamIngestor().ingest([InboundRecord(raw=LINES["latin-1 byte"], transport="syslog-udp", input_name="t")])
    with isolated_db.get_connection() as conn:
        # make the first row look like it was written before exact preservation: hash of the UTF-8
        # form of its text, no raw_hash_of. Its chain record is rebuilt to match, as it would have been.
        r = conn.execute("SELECT id, raw_text FROM raw_logs").fetchone()
        legacy_hash = Hasher.hash_raw_bytes(r["raw_text"])
        conn.execute("UPDATE raw_logs SET raw_hash = ?, raw_hash_of = NULL WHERE id = ?", (legacy_hash, r["id"]))
        ev = conn.execute("SELECT id, normalized_json FROM normalized_events WHERE raw_id = ?", (r["id"],)).fetchone()
        record = Hasher.compute_record_hash(Hasher.GENESIS_PREV_HASH, 1, legacy_hash, ev["normalized_json"])
        conn.execute("UPDATE integrity_ledger SET raw_hash = ?, record_hash = ? WHERE sequence_num = 1",
                     (legacy_hash, record))
        conn.commit()
    StreamIngestor().ingest([InboundRecord(raw=LINES["invalid utf-8"], transport="syslog-udp", input_name="t")])
    assert IntegrityLedger.verify_chain().is_valid, "a chain across both hash rules must verify"

    with isolated_db.get_connection() as conn:
        conn.execute("UPDATE raw_logs SET raw_text = replace(raw_text, 'blob', 'BLOB') WHERE raw_hash_of = 'bytes'")
        conn.commit()
    result = IntegrityLedger.verify_chain()
    assert not result.is_valid and any(i.issue_type == "RAW_HASH_MISMATCH" for i in result.issues)


def test_anyone_can_check_a_stored_line_against_its_hash_through_the_api(isolated_db):
    """Traceability, item (d), for a line that was not UTF-8: the API gives everything needed to
    verify it without trusting TRACELOG's word for it."""
    from backend.main import app
    received = LINES["latin-1 byte"] + b"\r\n"
    ev = StreamIngestor().ingest([InboundRecord(raw=received, transport="syslog-udp", input_name="t")])[0]
    detail = TestClient(app).get(f"/api/events/{ev.event_id}").json()
    line = detail["raw_text"].encode(detail["raw_encoding"])
    assert hashlib.sha256(line).hexdigest() == detail["raw_hash"] and detail["raw_hash_verified"]
    assert line + FRAMING_BYTES[detail["raw_framing"]] == received


def test_hec_keeps_object_events_readable_and_refuses_bodies_that_are_not_utf8(isolated_db, monkeypatch):
    from backend.connectors.engine import engine
    from backend.main import app
    captured = []
    monkeypatch.setattr(engine, "submit", lambda records: captured.extend(records))
    client = TestClient(app)
    ok = client.post("/services/collector/event", json={"event": {"msg": "login from Jörg", "src": "10.0.0.8"}})
    assert ok.status_code == 200 and captured
    assert captured[0].raw.decode("utf-8") == '{"msg":"login from Jörg","src":"10.0.0.8"}'
    bad = client.post("/services/collector/event", content=b'{"event": "caf\xe9"}',
                      headers={"Content-Type": "application/json"})
    assert bad.status_code == 400 and bad.json()["code"] == 6
