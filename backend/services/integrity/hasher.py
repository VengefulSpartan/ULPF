import hashlib
import json
from typing import Dict, Any

class Hasher:
    """
    Cryptographic SHA-256 hashing and canonical serialization utilities.
    Ensures bit-for-bit repeatability and strict tamper detection.
    """
    GENESIS_PREV_HASH = "0" * 64

    @classmethod
    def hash_raw_bytes(cls, raw_data: str | bytes) -> str:
        """
        Calculates SHA-256 hash of the exact raw bytes or string.
        """
        if isinstance(raw_data, str):
            payload_bytes = raw_data.encode("utf-8")
        else:
            payload_bytes = raw_data
        return hashlib.sha256(payload_bytes).hexdigest()

    @classmethod
    def canonical_json(cls, data: Dict[str, Any]) -> str:
        """
        Canonical JSON serialization:
        - Sorted keys
        - No extra whitespace (separators=(',', ':'))
        - UTF-8 deterministic encoding
        """
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    @classmethod
    def compute_record_hash(
        cls,
        prev_hash: str,
        sequence_num: int,
        raw_hash: str,
        normalized_data: Dict[str, Any] | str
    ) -> str:
        """
        Computes the chained record hash:
        H( prev_hash + ":" + sequence_num + ":" + raw_hash + ":" + canonical_json )
        """
        if isinstance(normalized_data, dict):
            canonical_str = cls.canonical_json(normalized_data)
        else:
            canonical_str = normalized_data.strip()

        preimage = f"{prev_hash}:{sequence_num}:{raw_hash}:{canonical_str}"
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
