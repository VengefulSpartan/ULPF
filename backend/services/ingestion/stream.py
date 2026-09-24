"""
Batched, lossless ingestion — the one writer every ingest path goes through: streamed logs
(syslog, HEC, OTLP, files, Kafka), file uploads, and lines sent to the API.

What "lossless" means here, precisely (docs/adr/0002-raw-preservation.md):

- the bytes of the line are kept exactly. The only thing removed is one line terminator —
  LF or CRLF — which belongs to the transport, not the event, and which one it was is recorded
  in raw_logs.raw_framing, so the bytes as they arrived can be rebuilt too;
- bytes that are not valid UTF-8 are decoded as Latin-1, which maps every byte to one character,
  and the encoding is recorded, so raw_text.encode(raw_encoding) is always the original bytes;
- raw_hash is SHA-256 of those original bytes (raw_hash_of = 'bytes'), so the hash proves what
  the device sent, not a re-encoding of it. Rows written before this carried a hash of the text's
  UTF-8 form (raw_hash_of NULL); for UTF-8 lines the two are identical, and the verifier knows both;
- a line that fails to parse is still archived, hashed and chained (as an OCSF Base Event carrying
  the parse error), so nothing received is ever dropped;
- a whole batch is written in one SQLite transaction;
- the sending device is registered as a source automatically, unless the caller already knows it
  (FixedSource: uploads and the API).
"""
import logging
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.services import jsonio
from backend.services.integrity.hasher import Hasher
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.normalization.ocsf_export import to_ocsf
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.services.parsing.dispatch import parse_log
from backend.services.parsing.formats import registry as format_registry
from backend.services.storage import db as db_module

logger = logging.getLogger("tracelog.stream")

_CATEGORY_BY_PACK = {
    "suricata_eve": "ids", "snort_alert": "ids", "zeek_json": "ids",
    "paloalto_panos": "firewall", "fortinet_fortigate": "firewall", "cisco_asa": "firewall",
    "checkpoint_log_exporter": "firewall", "juniper_srx": "firewall", "sophos_firewall": "firewall",
    "sonicwall_sonicos": "firewall", "pfsense_filterlog": "firewall",
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class InboundRecord:
    raw: bytes
    transport: str                      # syslog-udp | syslog-tcp | syslog-tls | hec | otlp | http | file | kafka
    input_name: str
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    received_at: str = field(default_factory=utcnow_iso)
    hints: Dict[str, Any] = field(default_factory=dict)   # source_name, vendor, product, hostname, csv_header


@dataclass
class StoredEvent:
    event_id: str
    raw_id: str
    source_id: str
    source_name: str
    sequence_num: int
    normalized: Dict[str, Any]
    format_detected: str = ""
    raw_hash: str = ""
    _ocsf: Optional[Dict[str, Any]] = None

    @property
    def ocsf(self) -> Dict[str, Any]:
        """The strict OCSF 1.1.0 form. Built when an output asks for it, not for every stored line:
        a deployment with no outputs configured never pays for it."""
        if self._ocsf is None:
            self._ocsf = to_ocsf(self.normalized)
        return self._ocsf


def split_framing(raw: bytes) -> Tuple[bytes, str]:
    """(the line's bytes, the terminator that framed it: 'CRLF', 'LF' or '').

    Exactly one terminator is removed. A second one, or a CR on its own, is part of the line."""
    if raw.endswith(b"\r\n"):
        return raw[:-2], "CRLF"
    if raw.endswith(b"\n"):
        return raw[:-1], "LF"
    return raw, ""


def decode_body(body: bytes) -> Tuple[str, str]:
    """Text and the encoding that reproduces the bytes: UTF-8 when valid, otherwise Latin-1."""
    try:
        return body.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return body.decode("latin-1"), "latin-1"


def decode_raw(raw: bytes) -> Tuple[str, str]:
    """Text and encoding of a received line, after its one line terminator."""
    return decode_body(split_framing(raw)[0])


_HOSTNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,62}")


class SourceResolver:
    """Maps (sender, detected vendor) to a row in `sources`, creating it on first sight."""

    def __init__(self, static_sources: Optional[List[Dict[str, Any]]] = None):
        self.static = static_sources or []
        self._cache: Dict[Tuple[str, str, str], Tuple[str, str]] = {}
        self._peer_hosts: Dict[Tuple[str, str, str], set] = {}
        self._lock = threading.Lock()

    def _static_match(self, rec: InboundRecord, hostname: Optional[str]) -> Optional[Dict[str, Any]]:
        for s in self.static:
            if s.get("match_ip") and s["match_ip"] == rec.peer_ip:
                return s
            if s.get("match_hostname") and hostname and s["match_hostname"].lower() == hostname.lower():
                return s
        return None

    def resolve(self, conn, rec: InboundRecord, parsed: Dict[str, Any], fmt: str) -> Tuple[str, str]:
        # The hostname inside the log beats one a forwarder attached (often the forwarder's own host).
        hostname = parsed.get("device_hostname") or (parsed.get("syslog") or {}).get("hostname") or \
            rec.hints.get("hostname")
        static = self._static_match(rec, hostname)
        vendor = (static or {}).get("vendor") or rec.hints.get("vendor") or parsed.get("vendor") or "Unknown"
        product = (static or {}).get("product") or rec.hints.get("product") or parsed.get("product") or "Syslog device"
        # The device's own hostname identifies it even behind a relay (rsyslog, Fluent Bit, Cribl, an OTel
        # Collector), where the peer address is the relay's. Fall back to the sender address.
        # A message without a hostname is given the hostname already seen from the same sender for the same
        # product, but only when that sender has shown exactly one (a relay for several devices stays ambiguous).
        # Not for lines no parser recognised: "Unknown" says nothing about which device sent them.
        device = hostname if hostname and _HOSTNAME_RE.fullmatch(hostname) else None
        peer_key = (rec.peer_ip or rec.input_name, vendor, product)
        with self._lock:
            seen = self._peer_hosts.setdefault(peer_key, set())
            if device:
                seen.add(device)
            elif len(seen) == 1 and vendor != "Unknown":
                device = next(iter(seen))
        who = device or rec.peer_ip or rec.input_name
        label = product if vendor.lower() in product.lower() else f"{vendor} {product}"
        name = (static or {}).get("name") or rec.hints.get("source_name") or f"{label} ({who})"
        key = (name, vendor, product)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        row = conn.execute("SELECT id, name FROM sources WHERE name = ?", (name,)).fetchone()
        if row:
            result = (row["id"], row["name"])
        else:
            source_id = str(uuid.uuid4())
            category = (static or {}).get("category") or _CATEGORY_BY_PACK.get(fmt, "network")
            conn.execute(
                "INSERT INTO sources (id, name, vendor, product, format_type, category, description, is_active, "
                "created_at, event_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 0)",
                (source_id, name, vendor, product, fmt, category,
                 f"Auto-registered from {rec.transport} input '{rec.input_name}'"
                 + (f" sender {rec.peer_ip}" if rec.peer_ip else ""), utcnow_iso()),
            )
            result = (source_id, name)
            logger.info("auto-registered source %s", name)
        with self._lock:
            self._cache[key] = result
        return result


EVENT_INSERT = """INSERT INTO normalized_events (id, sequence_num, raw_id, class_uid, class_name, category_uid,
   category_name, activity_id, activity_name, severity_id, severity, time, time_epoch_ms, src_ip,
   src_port, dst_ip, dst_port, protocol, action, disposition, user_name, finding_title,
   normalized_json, unmapped_json, parser_pack, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"""

RAW_INSERT = """INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected, status,
   raw_encoding, transport, input_name, peer_ip, received_at, format_id, raw_framing, raw_hash_of)
   VALUES (?, ?, ?, ?, datetime('now'), ?, 'ingested', ?, ?, ?, ?, ?, ?, ?, 'bytes')"""


def parser_pack_of(normalized: Dict[str, Any], fmt: str) -> str:
    """Which parser read this event: a vendor pack name, 'learned...', 'generic_inferred' or 'parse_error'.

    Stored in its own column so the dashboard can group by it without reading and parsing the
    JSON of every event. It is an index over what the event already says, not new information.
    """
    tp = (normalized.get("unmapped") or {}).get("tracelog_parse") or {}
    return tp.get("parser_pack") or fmt


def event_row(ev, event_id: str, seq: int, raw_id: str, normalized: Dict[str, Any], normalized_json: str,
              fmt: str) -> Tuple[Any, ...]:
    """The normalized_events row for one event, in EVENT_INSERT's column order."""
    return (event_id, seq, raw_id, ev.class_uid, ev.class_name, ev.category_uid, ev.category_name,
            ev.activity_id, ev.activity_name, ev.severity_id, ev.severity, ev.time, ev.time_epoch_ms,
            ev.src_endpoint.ip if ev.src_endpoint else None, ev.src_endpoint.port if ev.src_endpoint else None,
            ev.dst_endpoint.ip if ev.dst_endpoint else None, ev.dst_endpoint.port if ev.dst_endpoint else None,
            ev.connection_info.protocol_name if ev.connection_info else None, ev.action, ev.disposition,
            ev.user.name if ev.user else None, ev.finding.title if ev.finding else None,
            normalized_json, jsonio.dumps(ev.unmapped), parser_pack_of(normalized, fmt))


def store_event(conn, ev, event_id: str, seq: int, raw_id: str, raw_hash: str,
                fmt: str = "generic_inferred", head: Optional[Tuple[int, str]] = None) -> Dict[str, Any]:
    """Insert a normalised event and append it to the integrity chain (inside the caller's transaction).
    `head` is the chain head the caller already read, so it is not read again here."""
    normalized = ev.model_dump()
    # the stored JSON is the canonical form that the chain hashes, so each event is serialised once
    normalized_json = Hasher.canonical_json(normalized)
    conn.execute(EVENT_INSERT, event_row(ev, event_id, seq, raw_id, normalized, normalized_json, fmt))
    IntegrityLedger.append_event(conn=conn, event_id=event_id, raw_id=raw_id, raw_hash=raw_hash,
                                 normalized_data=normalized_json, head=head)
    return normalized


def note_format(conn, parsed: Dict[str, Any]) -> Optional[str]:
    """The registry format id for a line handled by the generic or a learned parser (None for vendor packs)."""
    tp = parsed.get("tracelog_parse")
    if not tp or not tp.get("format_id") or tp.get("standard") or tp.get("csv_header_row"):
        return None  # vendor packs, standard formats (CEF, LEEF) and CSV header rows are not new formats
    try:
        tp["format_id"] = format_registry.resolve(conn, tp)
    except Exception:
        logger.exception("could not resolve the log format")
    return tp["format_id"]


class FixedSource:
    """Resolver for callers that already know which source the lines belong to (uploads, the API)."""

    def __init__(self, source_id: str):
        self.source_id = source_id
        self._name: Optional[str] = None

    def resolve(self, conn, rec: InboundRecord, parsed: Dict[str, Any], fmt: str) -> Tuple[str, str]:
        if self._name is None:
            row = conn.execute("SELECT name FROM sources WHERE id = ?", (self.source_id,)).fetchone()
            if not row:
                raise ValueError(f"no source with id {self.source_id}")
            self._name = row["name"]
        return self.source_id, self._name


class StreamIngestor:
    OPTIMIZE_EVERY = 25   # batches between query-planner statistics refreshes

    def __init__(self, resolver: Optional[SourceResolver] = None):
        self.resolver = resolver or SourceResolver()
        self._batches = 0

    def ingest(self, records: List[InboundRecord]) -> List[StoredEvent]:
        prepared = []
        for rec in records:
            body, framing = split_framing(rec.raw)
            text, encoding = decode_body(body)
            if not text.strip():
                continue
            try:
                fmt, parsed = parse_log(text, rec.hints.get("csv_header"), bool(rec.hints.get("csv_header_row")))
            except Exception as exc:  # never lose a line because a parser failed
                logger.exception("parse failed")
                fmt, parsed = "parse_error", {"_format": "parse_error", "parse_error": str(exc)}
            prepared.append((rec, body, framing, text, encoding, fmt, parsed))
        if not prepared:
            return []

        stored: List[StoredEvent] = []
        counts: Dict[str, int] = {}
        database = db_module.db
        formats: List[Dict[str, Any]] = []
        raw_rows: List[Tuple[Any, ...]] = []
        event_rows: List[Tuple[Any, ...]] = []
        ledger_rows: List[Tuple[Any, ...]] = []
        with IntegrityLedger.write_lock, database.get_connection() as conn:
            # the chain head is read once for the batch and then carried in memory: the events are
            # linked in the same order, with the same hashes, without a query per line
            last_seq, prev_hash = IntegrityLedger.chain_head(conn)
            for rec, body, framing, text, encoding, fmt, parsed in prepared:
                source_id, source_name = self.resolver.resolve(conn, rec, parsed, fmt)
                raw_id, event_id = str(uuid.uuid4()), str(uuid.uuid4())
                raw_hash = Hasher.hash_raw_bytes(body)          # the bytes as received, not a re-encoding
                format_id = note_format(conn, parsed)
                raw_rows.append((raw_id, source_id, text, raw_hash, fmt, encoding, rec.transport, rec.input_name,
                                 rec.peer_ip, rec.received_at, format_id, framing))
                if format_id:
                    formats.append({"format_id": format_id, "tp": parsed["tracelog_parse"], "raw_id": raw_id,
                                    "raw_text": text, "source_name": source_name})
                seq = last_seq + 1
                try:
                    ev = OCSFNormalizer.normalize(parsed, text, raw_id, raw_hash,
                                                  vendor=parsed.get("vendor") or rec.hints.get("vendor") or "Generic",
                                                  product=parsed.get("product") or rec.hints.get("product") or "Device",
                                                  sequence_num=seq)
                except Exception as exc:
                    logger.exception("normalisation failed")
                    ev = OCSFNormalizer.normalize({"_ocsf_class": 0, "parse_error": str(exc)}, text, raw_id,
                                                  raw_hash, sequence_num=seq)
                ev.id = event_id
                ev.unmapped.setdefault("transport", rec.transport)
                if rec.hints.get("hostname") and not ev.unmapped.get("device_hostname"):
                    # e.g. host.name from an OTel Collector or `host` from a HEC forwarder; outputs use it as the
                    # event's host (Splunk host, syslog HOSTNAME, GELF host) instead of the relay's address
                    ev.unmapped["device_hostname"] = rec.hints["hostname"]
                if rec.peer_ip:
                    ev.unmapped.setdefault("sender_ip", rec.peer_ip)
                normalized = ev.model_dump()
                # serialised once: the stored JSON is the canonical form the chain hashes
                normalized_json = Hasher.canonical_json(normalized)
                record_hash = IntegrityLedger.link(seq, prev_hash, raw_hash, normalized_json)
                event_rows.append(event_row(ev, event_id, seq, raw_id, normalized, normalized_json, fmt))
                ledger_rows.append((seq, event_id, raw_id, raw_hash, record_hash, prev_hash))
                last_seq, prev_hash = seq, record_hash
                counts[source_id] = counts.get(source_id, 0) + 1
                stored.append(StoredEvent(event_id, raw_id, source_id, source_name, seq, normalized,
                                          format_detected=fmt, raw_hash=raw_hash))
            conn.executemany(RAW_INSERT, raw_rows)
            conn.executemany(EVENT_INSERT, event_rows)
            IntegrityLedger.insert_links(conn, ledger_rows)
            for source_id, n in counts.items():
                conn.execute("UPDATE sources SET event_count = event_count + ?, last_event_at = datetime('now') "
                             "WHERE id = ?", (n, source_id))
            if formats:
                try:
                    format_registry.note_batch(conn, formats)
                except Exception:  # counting formats must never cost a log line
                    logger.exception("could not update the format registry")
            conn.commit()
        self._batches += 1
        if self._batches % self.OPTIMIZE_EVERY == 0:
            database.optimize()
        return stored
