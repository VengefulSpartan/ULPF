"""
The fast path must produce exactly what the plain path produced.

Speeding up ingestion touched three things that events are judged by: the JSON that is
hashed into the chain, the timestamp reader, and the field-name lookup. Each test here
runs the fast implementation and a plain reference implementation over the whole sample
corpus and demands the same answer, because a faster pipeline that changes one field is
worth nothing.

The last test is a floor, not a benchmark: it fails if ingestion collapses to a fraction
of its speed. scripts/benchmark.py is where the real numbers come from.
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from backend.services import jsonio, timefmt
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.integrity.hasher import Hasher
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.normalization.ocsf_normalizer import IndexedFields, OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.vendors.common import _is_yearless, iso_from_formats
from tests.test_vendor_packs import (ASA_AAA_FAIL, ASA_DENY, CP_DROP, FORTI_TRAFFIC, FORTI_VPN_FAIL,
                                     PAN_THREAT, PAN_TRAFFIC, PFSENSE, SNORT, SONICWALL, SOPHOS, SRX_DENY,
                                     SURICATA, ZEEK)
from tests.unseen_corpus import CORPUS

LINES = [PAN_TRAFFIC, PAN_THREAT, FORTI_TRAFFIC, FORTI_VPN_FAIL, ASA_DENY, ASA_AAA_FAIL, CP_DROP,
         SRX_DENY, SOPHOS, SONICWALL, PFSENSE, SURICATA, ZEEK, SNORT] + \
        [c["line"] for c in CORPUS]


def _reference_canonical(data) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reference_iso(value, formats, tz_offset=None):
    """iso_from_formats as it was written before the format memo: try every format, in order."""
    if not value:
        return None
    import re
    text = re.sub(r"\s+", " ", value.strip())
    now = datetime.now(timezone.utc)
    for fmt in formats:
        yearless = _is_yearless(fmt)
        try:
            dt = datetime.strptime(f"{now.year} {text}", f"%Y {fmt}") if yearless else datetime.strptime(text, fmt)
        except ValueError:
            continue
        if yearless and dt.replace(tzinfo=timezone.utc) > now + timedelta(days=2):
            dt = dt.replace(year=now.year - 1)
        if dt.tzinfo is None:
            tz = timezone.utc
            if tz_offset:
                m = re.match(r"^([+-])(\d{2}):?(\d{2})$", tz_offset.strip())
                if m:
                    delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
                    tz = timezone(delta if m.group(1) == "+" else -delta)
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc).isoformat()
    return None


def _reference_find_first(data, aliases):
    """find_first before the lower-cased index: scan the dict once per alias."""
    for alias in aliases:
        if alias in data and data[alias] is not None:
            return data[alias]
        for k, v in data.items():
            if k.lower() == alias.lower() and v is not None:
                return v
    return None


def test_canonical_json_is_byte_identical_to_the_standard_library():
    """The canonical form is the hash preimage: an event written with orjson installed has to
    verify on a machine without it."""
    for line in LINES:
        _, parsed = parse_log(line)
        event = OCSFNormalizer.normalize(parsed, line, "raw-1", "hash-1").model_dump()
        assert jsonio.canonical(event) == _reference_canonical(event)
        assert jsonio.loads(jsonio.canonical(event)) == event


def test_json_helpers_refuse_what_the_standard_library_refuses():
    with pytest.raises(TypeError):
        jsonio.dumps({"when": datetime.now(timezone.utc)})


@pytest.mark.parametrize("formats", [
    ("%b %d %H:%M:%S",),
    ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S"),
    ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S"),
])
def test_remembering_a_timestamp_format_gives_the_same_answer_as_trying_them_all(formats):
    samples = ["Sep 20 14:00:15", "Dec  1 09:03:00", "2026-09-21 10:15:02", "2026/09/21 10:15:02",
               "21/Sep/2026:10:15:02 +0530", "2026-09-21T10:15:02+05:30", "not a time at all", ""]
    timefmt.clear()
    for value in samples:
        assert iso_from_formats(value, formats) == _reference_iso(value, formats)
    for value in samples:                      # again, now that the shapes are remembered
        assert iso_from_formats(value, formats) == _reference_iso(value, formats)
    assert iso_from_formats("Sep 20 14:00:15", formats, tz_offset="+0530") == \
        _reference_iso("Sep 20 14:00:15", formats, tz_offset="+0530")


def test_field_lookup_by_index_matches_the_plain_scan():
    for line in LINES:
        _, parsed = parse_log(line)
        indexed = IndexedFields(parsed)
        for aliases in (OCSFNormalizer.SRC_IP_ALIASES, OCSFNormalizer.DST_PORT_ALIASES,
                        OCSFNormalizer.USER_ALIASES, OCSFNormalizer.ACTION_ALIASES,
                        OCSFNormalizer.PROTO_ALIASES, ["signature", "msg", "Alert"]):
            assert OCSFNormalizer.find_first(indexed, aliases) == _reference_find_first(parsed, aliases)


def test_a_batch_writes_the_same_chain_a_line_at_a_time_would(isolated_db):
    """Linking a batch in memory must give the sequence numbers and hashes the old one-query-per-line
    path gave, and the chain must verify."""
    stored = StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t")
                                      for l in LINES])
    assert len(stored) == len(LINES)
    assert [s.sequence_num for s in stored] == list(range(1, len(LINES) + 1))

    with isolated_db.get_connection() as conn:
        rows = conn.execute(
            "SELECT l.sequence_num, l.raw_hash, l.record_hash, l.prev_hash, n.normalized_json "
            "FROM integrity_ledger l JOIN normalized_events n ON n.id = l.event_id "
            "ORDER BY l.sequence_num").fetchall()
    prev = Hasher.GENESIS_PREV_HASH
    for row in rows:
        assert row["prev_hash"] == prev
        expected = Hasher.compute_record_hash(prev, row["sequence_num"], row["raw_hash"],
                                              json.loads(row["normalized_json"]))
        assert row["record_hash"] == expected
        prev = row["record_hash"]
    assert IntegrityLedger.verify_chain().is_valid


def test_the_parser_column_counts_what_reading_every_event_counted(isolated_db):
    from backend.services.analytics.quality import parse_breakdown
    StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t")
                             for l in LINES])
    fast = parse_breakdown(isolated_db.get_connection())
    with isolated_db.get_connection() as conn:
        rows = conn.execute(
            "SELECT COALESCE(json_extract(n.unmapped_json, '$.tracelog_parse.parser_pack'), r.format_detected) "
            "AS pack, COUNT(*) AS n FROM normalized_events n JOIN raw_logs r ON r.id = n.raw_id "
            "WHERE n.superseded_by IS NULL GROUP BY pack").fetchall()
    assert fast["by_parser"] == {r["pack"]: r["n"] for r in rows}
    assert fast["total"] == len(LINES)


def test_search_finds_a_line_by_a_word_inside_it(isolated_db):
    from backend.api.events import list_events
    StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t")
                             for l in LINES])
    hits = list_events("10.20.4.5", None, None, None, None, 50, 0, False)   # an address in the PAN line
    assert hits["count"] >= 1 and any("10.20.4.5" in e["raw_text"] for e in hits["events"])
    assert list_events("zzz-nothing-matches-this", None, None, None, None, 50, 0, False)["count"] == 0


def test_ingestion_stays_far_above_a_trickle(isolated_db):
    """A floor, not a benchmark: this fails if the write path goes back to a query per line."""
    lines = (LINES * 40)[:2000]
    ingestor = StreamIngestor()
    start = time.perf_counter()
    for i in range(0, len(lines), 500):
        ingestor.ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t")
                         for l in lines[i:i + 500]])
    rate = len(lines) / (time.perf_counter() - start)
    assert rate > 300, f"{rate:.0f} events/s is far below what this path measures"
