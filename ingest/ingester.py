import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import structlog

from ingest.models import RawEvent
from storage.archive import RawArchiveManager, HashChainLedger

logger = structlog.get_logger()


class IngestPipeline:
    """Core ingestion pipeline responsible for assigning metadata, archiving raw bytes,
    and recording hash-chain ledger entries.
    """

    def __init__(
        self,
        archive_manager: Optional[RawArchiveManager] = None,
        ledger: Optional[HashChainLedger] = None
    ):
        self.archive_manager = archive_manager or RawArchiveManager()
        self.ledger = ledger or HashChainLedger()

    def process_raw_event(self, raw_bytes: bytes, source_metadata: Optional[Dict[str, Any]] = None) -> RawEvent:
        """Process raw input bytes losslessly before parsing."""
        if source_metadata is None:
            source_metadata = {}

        event_uuid = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        receipt_ts = now.isoformat()
        date_str = now.strftime("%Y-%m-%d")

        # Compute SHA256 of raw bytes
        sha256_hex = hashlib.sha256(raw_bytes).hexdigest()

        # Archive raw bytes BEFORE any parsing
        object_path = self.archive_manager.archive_raw(date_str, event_uuid, raw_bytes)

        # Append to hash chain ledger
        self.ledger.append(event_uuid, sha256_hex)

        # Build raw event
        metadata = dict(source_metadata)
        metadata["archive_path"] = object_path

        event = RawEvent(
            uuid=event_uuid,
            receipt_ts=receipt_ts,
            source_metadata=metadata,
            raw_bytes=raw_bytes,
            sha256=sha256_hex
        )

        logger.info(
            "raw_event_ingested",
            uuid=event_uuid,
            sha256=sha256_hex,
            size=len(raw_bytes),
            archive_path=object_path
        )
        return event
