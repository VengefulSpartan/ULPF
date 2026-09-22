"""
Batched, lossless ingestion for streamed logs (syslog, HEC, OTLP, files, Kafka).

Differences from the interactive single-line API path:
- raw bytes are kept exactly: only transport framing (a trailing CR/LF) is
  removed; bytes that are not valid UTF-8 are decoded as Latin-1, which maps
  every byte to one character, and the encoding is recorded so the original
  bytes can always be reproduced;
- a line that fails to parse is still archived, hashed and chained (as an OCSF
  Base Event carrying the parse error), so nothing received is ever dropped;
- a whole batch is written in one SQLite transaction;
- the sending device is registered as a source automatically.
"""
import json
import logging
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
    hints: Dict[str, str] = field(default_factory=dict)   # source_name, vendor, product, hostname


@dataclass
class StoredEvent:
    event_id: str
    raw_id: str
    source_id: str
    source_name: str
    sequence_num: int
    normalized: Dict[str, Any]
    ocsf: Dict[str, Any]


def decode_raw(raw: bytes) -> Tuple[str, str]:
    body = raw.rstrip(b"\r\n")
    try:
        return body.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return body.decode("latin-1"), "latin-1"


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


def store_event(conn, ev, event_id: str, seq: int, raw_id: str, raw_hash: str) -> Dict[str, Any]:
    """Insert a normalised event and append it to the integrity chain (inside the caller's transaction)."""
    normalized = ev.model_dump()
    conn.execute(
        """INSERT INTO normalized_events (id, sequence_num, raw_id, class_uid, class_name, category_uid,
           category_name, activity_id, activity_name, severity_id, severity, time, time_epoch_ms, src_ip,
           src_port, dst_ip, dst_port, protocol, action, disposition, user_name, finding_title,
           normalized_json, unmapped_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
        (event_id, seq, raw_id, ev.class_uid, ev.class_name, ev.category_uid, ev.category_name,
         ev.activity_id, ev.activity_name, ev.severity_id, ev.severity, ev.time, ev.time_epoch_ms,
         ev.src_endpoint.ip if ev.src_endpoint else None, ev.src_endpoint.port if ev.src_endpoint else None,
         ev.dst_endpoint.ip if ev.dst_endpoint else None, ev.dst_endpoint.port if ev.dst_endpoint else None,
         ev.connection_info.protocol_name if ev.connection_info else None, ev.action, ev.disposition,
         ev.user.name if ev.user else None, ev.finding.title if ev.finding else None,
         json.dumps(normalized), json.dumps(ev.unmapped)),
    )
    IntegrityLedger.append_event(conn=conn, event_id=event_id, raw_id=raw_id, raw_hash=raw_hash,
                                 normalized_data=normalized)
    return normalized


def note_format(conn, parsed: Dict[str, Any]) -> Optional[str]:
    """The registry format id for a line handled by the generic or a learned parser (None for vendor packs)."""
    tp = parsed.get("tracelog_parse")
    if not tp or not tp.get("format_id") or tp.get("standard"):
        return None  # vendor packs and standard formats (CEF, LEEF) are not new formats
    try:
        tp["format_id"] = format_registry.resolve(conn, tp)
    except Exception:
        logger.exception("could not resolve the log format")
    return tp["format_id"]


class StreamIngestor:
    def __init__(self, resolver: Optional[SourceResolver] = None):
        self.resolver = resolver or SourceResolver()

    def ingest(self, records: List[InboundRecord]) -> List[StoredEvent]:
        prepared = []
        for rec in records:
            text, encoding = decode_raw(rec.raw)
            if not text.strip():
                continue
            try:
                fmt, parsed = parse_log(text)
            except Exception as exc:  # never lose a line because a parser failed
                logger.exception("parse failed")
                fmt, parsed = "parse_error", {"_format": "parse_error", "parse_error": str(exc)}
            prepared.append((rec, text, encoding, fmt, parsed))
        if not prepared:
            return []

        stored: List[StoredEvent] = []
        counts: Dict[str, int] = {}
        database = db_module.db
        formats: List[Dict[str, Any]] = []
        with IntegrityLedger.write_lock, database.get_connection() as conn:
            for rec, text, encoding, fmt, parsed in prepared:
                source_id, source_name = self.resolver.resolve(conn, rec, parsed, fmt)
                raw_id, event_id = str(uuid.uuid4()), str(uuid.uuid4())
                raw_hash = Hasher.hash_raw_bytes(text)
                format_id = note_format(conn, parsed)
                conn.execute(
                    "INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected, status, "
                    "raw_encoding, transport, input_name, peer_ip, received_at, format_id) "
                    "VALUES (?, ?, ?, ?, datetime('now'), ?, 'ingested', ?, ?, ?, ?, ?, ?)",
                    (raw_id, source_id, text, raw_hash, fmt, encoding, rec.transport, rec.input_name,
                     rec.peer_ip, rec.received_at, format_id),
                )
                if format_id:
                    formats.append({"format_id": format_id, "tp": parsed["tracelog_parse"], "raw_id": raw_id,
                                    "raw_text": text, "source_name": source_name})
                latest = IntegrityLedger.get_latest_entry(conn)
                seq = (latest["sequence_num"] + 1) if latest else 1
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
                normalized = store_event(conn, ev, event_id, seq, raw_id, raw_hash)
                counts[source_id] = counts.get(source_id, 0) + 1
                stored.append(StoredEvent(event_id, raw_id, source_id, source_name, seq, normalized,
                                          to_ocsf(normalized)))
            for source_id, n in counts.items():
                conn.execute("UPDATE sources SET event_count = event_count + ?, last_event_at = datetime('now') "
                             "WHERE id = ?", (n, source_id))
            if formats:
                try:
                    format_registry.note_batch(conn, formats)
                except Exception:  # counting formats must never cost a log line
                    logger.exception("could not update the format registry")
            conn.commit()
        return stored
