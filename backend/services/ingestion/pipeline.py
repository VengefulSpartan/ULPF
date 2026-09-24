"""
Ingestion for callers that already know the source: a line sent to the API, a batch of lines, and
file uploads from the dashboard.

These used to have their own writer, and it was not lossless: it stripped whitespace from API lines,
and uploads were decoded with errors="replace", so a byte that was not valid UTF-8 became U+FFFD and
was gone for good. Now every path goes through the one batched writer (stream.StreamIngestor) with
a FixedSource resolver, so an uploaded or posted line is kept exactly as a streamed one is — same
decoding, same framing record, same hash of the bytes received — and uploads are written a batch per
transaction instead of a transaction per line.
"""
import logging
from typing import Any, Dict, Iterable, List, Union

from backend.services.ingestion.stream import FixedSource, InboundRecord, StoredEvent, StreamIngestor, decode_raw
from backend.services.parsing.csvheader import header_of

logger = logging.getLogger("tracelog.pipeline")

BATCH = 1000
Line = Union[str, bytes]


def _as_bytes(line: Line) -> bytes:
    # text from the API arrived as UTF-8 JSON, so those are its bytes
    return line if isinstance(line, bytes) else line.encode("utf-8")


def _route(stored: List[StoredEvent]) -> None:
    """Hand stored events to the configured outputs (a no-op where the connector engine is not
    running; startup recovery then sends anything an output still owes)."""
    if not stored:
        return
    try:
        from backend.connectors.engine import engine
        engine.route(stored)
    except Exception:
        logger.exception("could not hand %d events to the outputs", len(stored))


class IngestionPipeline:
    """Receive -> archive the exact bytes -> parse -> normalise to OCSF -> hash-chain -> deliver."""

    @classmethod
    def ingest_single_log(cls, raw_text: str, source_id: str, source_vendor: str = "Generic",
                          source_product: str = "Perimeter Device", transport: str = "api") -> Dict[str, Any]:
        """Ingest one line exactly as given — leading and trailing whitespace included."""
        if not raw_text or not raw_text.strip():
            raise ValueError("Log line cannot be empty")
        record = InboundRecord(raw=_as_bytes(raw_text), transport=transport, input_name=transport,
                               hints={"vendor": source_vendor, "product": source_product})
        stored = StreamIngestor(FixedSource(source_id)).ingest([record])
        if not stored:
            raise ValueError("Log line cannot be empty")
        _route(stored)
        ev = stored[0]
        return {
            "success": True,
            "raw_id": ev.raw_id,
            "event_id": ev.event_id,
            "sequence_num": ev.sequence_num,
            "raw_hash": ev.raw_hash,
            "format_detected": ev.format_detected,
            "ocsf_class": ev.normalized.get("class_name"),
            "severity": ev.normalized.get("severity"),
        }

    @classmethod
    def ingest_batch(cls, lines: Iterable[Line], source_id: str, source_vendor: str = "Generic",
                     source_product: str = "Perimeter Device", transport: str = "api") -> Dict[str, Any]:
        """
        Ingest many lines for one source. Every line that is not blank is archived — including
        lines that start with '#', which are often a format's own header (W3C '#Fields:', Zeek) and
        are part of what the device wrote.
        """
        lines = list(lines)
        ingestor = StreamIngestor(FixedSource(source_id))
        hints = {"vendor": source_vendor, "product": source_product}
        per_line = csv_hints(lines, hints)
        ingested = 0
        for i in range(0, len(lines), BATCH):
            records = [InboundRecord(raw=_as_bytes(line), transport=transport, input_name=transport, hints=h)
                       for line, h in zip(lines[i:i + BATCH], per_line[i:i + BATCH])]
            stored = ingestor.ingest(records)
            ingested += len(stored)
            _route(stored)
        return {"total": len(lines), "ingested": ingested, "skipped_blank": len(lines) - ingested,
                "failed": 0, "errors": []}


def csv_hints(lines: List[Line], base: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Hints for each line of a file or batch: when its first non-blank line is a CSV header
    (csvheader.py), that line is marked as the header and every line after it carries the header,
    so its columns are read by name. Otherwise every line gets the base hints unchanged."""
    first = [i for i, line in enumerate(lines) if decode_raw(_as_bytes(line))[0].strip()][:2]
    header = None
    if first:
        texts = [decode_raw(_as_bytes(lines[i]))[0] for i in first]
        header = header_of(texts[0], texts[1] if len(texts) > 1 else None)
    if not header:
        return [base] * len(lines)
    start = first[0]
    return [base if i < start else {**base, "csv_header_row": True} if i == start else {**base, "csv_header": header}
            for i in range(len(lines))]


def split_upload(content: bytes) -> List[bytes]:
    """
    An uploaded file's lines, as bytes, each with its own terminator still attached so the writer
    records whether it was LF or CRLF. Nothing is decoded here: decoding is the writer's job, and it
    never replaces a byte.
    """
    parts = content.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])          # a last line with no terminator
    return lines
