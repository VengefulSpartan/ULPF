import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from backend.services.storage.db import db
from backend.services.integrity.hasher import Hasher
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.parsing.dispatch import parse_log
from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
from backend.models.event import OCSFEvent, RawLogRecord

logger = logging.getLogger("ulpf.pipeline")

class IngestionPipeline:
    """
    Core Ingestion and Pre-processing Pipeline:
    Ingestion -> Lossless Raw Storage -> Parsing -> OCSF Normalization -> Integrity Ledger
    """

    @classmethod
    def ingest_single_log(
        cls,
        raw_text: str,
        source_id: str,
        source_vendor: str = "Generic",
        source_product: str = "Perimeter Device"
    ) -> Dict[str, Any]:
        """
        Executes end-to-end ingestion of a single raw log string within an atomic SQLite transaction.
        """
        raw_text = raw_text.strip()
        if not raw_text:
            raise ValueError("Log line cannot be empty")

        raw_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        raw_hash = Hasher.hash_raw_bytes(raw_text)

        # 1. Parse log
        format_detected, parsed_data = parse_log(raw_text)

        with IntegrityLedger.write_lock, db.get_connection() as conn:
            cursor = conn.cursor()

            # 2. Insert into raw_logs (lossless byte preservation)
            from backend.services.ingestion.stream import note_format
            format_id = note_format(conn, parsed_data)
            cursor.execute(
                """
                INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected, status,
                                      format_id)
                VALUES (?, ?, ?, ?, datetime('now'), ?, 'ingested', ?)
                """,
                (raw_id, source_id, raw_text, raw_hash, format_detected, format_id)
            )

            # 3. Determine next sequence number (read once, handed to the ledger below)
            last_seq, prev_hash = IntegrityLedger.chain_head(conn)
            seq_num = last_seq + 1

            # 4. Normalize to OCSF v1.1.0
            ocsf_event: OCSFEvent = OCSFNormalizer.normalize(
                parsed_data=parsed_data,
                raw_text=raw_text,
                raw_id=raw_id,
                raw_hash=raw_hash,
                vendor=source_vendor,
                product=source_product,
                sequence_num=seq_num
            )
            # Override generated id with our event_id
            ocsf_event.id = event_id

            # 5. Store the event and append it to the integrity chain (same writer as streamed logs)
            from backend.services.ingestion.stream import store_event
            normalized_dict = store_event(conn, ocsf_event, event_id, seq_num, raw_id, raw_hash,
                                          fmt=format_detected, head=(last_seq, prev_hash))

            if format_id:
                from backend.services.parsing.formats import registry as format_registry
                row = cursor.execute("SELECT name FROM sources WHERE id = ?", (source_id,)).fetchone()
                try:
                    format_registry.note_batch(conn, [{"format_id": format_id, "tp": parsed_data["tracelog_parse"],
                                                       "raw_id": raw_id, "raw_text": raw_text,
                                                       "source_name": row[0] if row else None}])
                except Exception:
                    logger.exception("could not update the format registry")

            # 7. Update source event stats
            cursor.execute(
                """
                UPDATE sources 
                SET event_count = event_count + 1, last_event_at = datetime('now')
                WHERE id = ?
                """,
                (source_id,)
            )

            conn.commit()

        # Forward to the configured outputs like streamed logs (a no-op where the connector engine
        # is not running; startup recovery then sends anything an output still owes).
        try:
            from backend.connectors.engine import engine
            engine.route_normalized(normalized_dict, source_id)
        except Exception:
            logging.getLogger("ulpf.pipeline").exception("could not hand event %s to the outputs", event_id)

        return {
            "success": True,
            "raw_id": raw_id,
            "event_id": event_id,
            "sequence_num": seq_num,
            "raw_hash": raw_hash,
            "format_detected": format_detected,
            "ocsf_class": ocsf_event.class_name,
            "severity": ocsf_event.severity
        }

    @classmethod
    def ingest_batch(
        cls,
        lines: List[str],
        source_id: str,
        source_vendor: str = "Generic",
        source_product: str = "Perimeter Device"
    ) -> Dict[str, Any]:
        """
        Ingests a batch of raw log lines sequentially preserving monotonic order.
        """
        success_count = 0
        failed_count = 0
        errors = []

        for idx, line in enumerate(lines):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue
            try:
                cls.ingest_single_log(
                    raw_text=clean_line,
                    source_id=source_id,
                    source_vendor=source_vendor,
                    source_product=source_product
                )
                success_count += 1
            except Exception as e:
                failed_count += 1
                errors.append(f"Line {idx + 1}: {str(e)}")

        return {
            "total": len(lines),
            "ingested": success_count,
            "failed": failed_count,
            "errors": errors[:10]
        }
