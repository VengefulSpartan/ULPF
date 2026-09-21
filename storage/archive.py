import os
import io
import hashlib
from datetime import datetime, timezone
from typing import List, Tuple, Optional
import structlog

from minio import Minio
from ingest.models import HashChainBlock

logger = structlog.get_logger()


class RawArchiveManager:
    """Manages lossless raw log byte archiving in MinIO with local fallback."""

    def __init__(self, bucket_name: str = "ulpf-raw-archive"):
        self.bucket_name = bucket_name
        self.host = os.getenv("MINIO_HOST", "localhost")
        self.port = os.getenv("MINIO_PORT", "9000")
        self.endpoint = f"{self.host}:{self.port}"
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        self.secure = os.getenv("MINIO_SECURE", "false").lower() == "true"
        
        self.local_archive_dir = os.path.join(os.getcwd(), ".data", "archive")
        os.makedirs(self.local_archive_dir, exist_ok=True)
        
        self._minio_client: Optional[Minio] = None
        self._init_minio()

    def _init_minio(self) -> None:
        import socket
        try:
            with socket.create_connection((self.host, int(self.port)), timeout=0.05):
                pass
        except Exception as exc:
            logger.warning("minio_port_unreachable_using_local_fallback", error=str(exc))
            self._minio_client = None
            return

        try:
            client = Minio(
                endpoint=self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure
            )
            # Try bucket check
            if not client.bucket_exists(self.bucket_name):
                client.make_bucket(self.bucket_name)
            self._minio_client = client
            logger.info("minio_archive_initialized", bucket=self.bucket_name)
        except Exception as exc:
            logger.warning("minio_unavailable_using_local_fallback", error=str(exc))
            self._minio_client = None

    def archive_raw(self, date_str: str, uuid_str: str, raw_bytes: bytes) -> str:
        """Archive raw bytes byte-for-byte under raw/{date}/{uuid}."""
        object_path = f"raw/{date_str}/{uuid_str}"

        if self._minio_client is not None:
            try:
                data_stream = io.BytesIO(raw_bytes)
                self._minio_client.put_object(
                    bucket_name=self.bucket_name,
                    object_name=object_path,
                    data=data_stream,
                    length=len(raw_bytes),
                    content_type="application/octet-stream"
                )
                logger.info("raw_archived_minio", object_path=object_path, size=len(raw_bytes))
                return object_path
            except Exception as exc:
                logger.error("minio_put_object_failed_falling_back_local", error=str(exc))

        # Local fallback storage
        local_path = os.path.join(self.local_archive_dir, object_path.replace("/", os.sep))
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(raw_bytes)
        logger.info("raw_archived_local", path=local_path, size=len(raw_bytes))
        return object_path

    def retrieve_raw(self, object_path: str) -> bytes:
        """Retrieve raw archived bytes byte-for-byte."""
        if self._minio_client is not None:
            try:
                response = self._minio_client.get_object(
                    bucket_name=self.bucket_name,
                    object_name=object_path
                )
                data = response.read()
                response.close()
                response.release_conn()
                return data
            except Exception as exc:
                logger.warning("minio_get_object_failed_trying_local", error=str(exc))

        local_path = os.path.join(self.local_archive_dir, object_path.replace("/", os.sep))
        if os.path.exists(local_path):
            with open(local_path, "rb") as f:
                return f.read()
        
        raise FileNotFoundError(f"Archived payload not found for object_path: {object_path}")


class HashChainLedger:
    """Tamper-evident hash chain ledger for archived raw log events."""

    def __init__(self):
        self.blocks: List[HashChainBlock] = []

    def append(self, uuid_str: str, sha256_hex: str) -> HashChainBlock:
        sequence = len(self.blocks) + 1
        prev_hash = "GENESIS" if sequence == 1 else self.blocks[-1].block_hash
        timestamp = datetime.now(timezone.utc).isoformat()
        
        raw_hash_data = f"{sequence}:{uuid_str}:{sha256_hex}:{prev_hash}"
        block_hash = hashlib.sha256(raw_hash_data.encode("utf-8")).hexdigest()

        block = HashChainBlock(
            sequence=sequence,
            uuid=uuid_str,
            sha256=sha256_hex,
            prev_hash=prev_hash,
            block_hash=block_hash,
            timestamp=timestamp
        )
        self.blocks.append(block)
        logger.info("hash_chain_block_appended", sequence=sequence, uuid=uuid_str, block_hash=block_hash)
        return block

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """Verify hash chain continuity and block hashes.
        
        Returns:
            (is_valid, tampered_sequence_number)
        """
        expected_prev_hash = "GENESIS"

        for idx, block in enumerate(self.blocks):
            # Check prev_hash link
            if block.prev_hash != expected_prev_hash:
                logger.error(
                    "hash_chain_link_broken",
                    sequence=block.sequence,
                    expected_prev=expected_prev_hash,
                    actual_prev=block.prev_hash
                )
                return False, block.sequence

            # Recompute block hash
            raw_hash_data = f"{block.sequence}:{block.uuid}:{block.sha256}:{block.prev_hash}"
            computed_block_hash = hashlib.sha256(raw_hash_data.encode("utf-8")).hexdigest()

            if block.block_hash != computed_block_hash:
                logger.error(
                    "hash_chain_block_tampered",
                    sequence=block.sequence,
                    expected_hash=computed_block_hash,
                    actual_hash=block.block_hash
                )
                return False, block.sequence

            expected_prev_hash = block.block_hash

        return True, None
