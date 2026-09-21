from pydantic import BaseModel, Field
from typing import Dict, Any
from datetime import datetime


class RawEvent(BaseModel):
    """Represents a raw ingested log event before any parsing or normalization."""
    uuid: str
    receipt_ts: str
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_bytes: bytes
    sha256: str


class HashChainBlock(BaseModel):
    """Represents a tamper-evident ledger entry in the hash chain."""
    sequence: int
    uuid: str
    sha256: str
    prev_hash: str
    block_hash: str
    timestamp: str
