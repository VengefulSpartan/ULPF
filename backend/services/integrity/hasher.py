import hashlib
from typing import Dict, Any

from backend.services import jsonio

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
    def stored_raw_hash(cls, raw_text: str, raw_encoding: str | None, raw_hash_of: str | None) -> str:
        """
        Recompute a stored line's raw_hash the way it was computed when it was written.

        'bytes' (every row written since exact preservation): SHA-256 of the bytes received, which
        raw_text.encode(raw_encoding) reproduces exactly. Older rows (NULL): SHA-256 of the text's
        UTF-8 form. For a line that was valid UTF-8 the two are the same hash.
        """
        if raw_hash_of == "bytes":
            return cls.hash_raw_bytes(raw_text.encode(raw_encoding or "utf-8"))
        return cls.hash_raw_bytes(raw_text)

    @classmethod
    def canonical_json(cls, data: Dict[str, Any]) -> str:
        """
        Canonical JSON serialization:
        - Sorted keys
        - No extra whitespace (separators=(',', ':'))
        - UTF-8 deterministic encoding
        """
        return jsonio.canonical(data)

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
