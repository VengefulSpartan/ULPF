import uuid
import json
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

        with db.get_connection() as conn:
            cursor = conn.cursor()

            # 2. Insert into raw_logs (lossless byte preservation)
            cursor.execute(
                """
                INSERT INTO raw_logs (id, source_id, raw_text, raw_hash, ingested_at, format_detected, status)
                VALUES (?, ?, ?, ?, datetime('now'), ?, 'ingested')
                """,
                (raw_id, source_id, raw_text, raw_hash, format_detected)
            )

            # 3. Determine next sequence number
            latest = IntegrityLedger.get_latest_entry(conn)
            seq_num = (latest["sequence_num"] + 1) if latest else 1

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

            normalized_dict = ocsf_event.model_dump()
            normalized_json_str = json.dumps(normalized_dict)
            unmapped_json_str = json.dumps(ocsf_event.unmapped)

            # 5. Insert into normalized_events
            cursor.execute(
                """
                INSERT INTO normalized_events (
                    id, sequence_num, raw_id, class_uid, class_name, category_uid, category_name,
                    activity_id, activity_name, severity_id, severity, time, time_epoch_ms,
                    src_ip, src_port, dst_ip, dst_port, protocol, action, disposition,
                    user_name, finding_title, normalized_json, unmapped_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    event_id, seq_num, raw_id,
                    ocsf_event.class_uid, ocsf_event.class_name,
                    ocsf_event.category_uid, ocsf_event.category_name,
                    ocsf_event.activity_id, ocsf_event.activity_name,
                    ocsf_event.severity_id, ocsf_event.severity,
                    ocsf_event.time, ocsf_event.time_epoch_ms,
                    ocsf_event.src_endpoint.ip if ocsf_event.src_endpoint else None,
                    ocsf_event.src_endpoint.port if ocsf_event.src_endpoint else None,
                    ocsf_event.dst_endpoint.ip if ocsf_event.dst_endpoint else None,
                    ocsf_event.dst_endpoint.port if ocsf_event.dst_endpoint else None,
                    ocsf_event.connection_info.protocol_name if ocsf_event.connection_info else None,
                    ocsf_event.action, ocsf_event.disposition,
                    ocsf_event.user.name if ocsf_event.user else None,
                    ocsf_event.finding.title if ocsf_event.finding else None,
                    normalized_json_str, unmapped_json_str
                )
            )

            # 6. Append to cryptographic integrity ledger
            IntegrityLedger.append_event(
                conn=conn,
                event_id=event_id,
                raw_id=raw_id,
                raw_hash=raw_hash,
                normalized_data=normalized_dict
            )

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
