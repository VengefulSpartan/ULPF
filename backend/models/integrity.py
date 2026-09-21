from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class LedgerEntry(BaseModel):
    sequence_num: int
    event_id: str
    raw_id: str
    raw_hash: str
    record_hash: str
    prev_hash: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class VerificationIssue(BaseModel):
    sequence_num: int
    event_id: str
    issue_type: str # HASH_MISMATCH, BROKEN_CHAIN, DELETED_RECORD, REORDERED_RECORD, RAW_HASH_MISMATCH
    description: str
    expected: str
    actual: str

class IntegrityVerificationResult(BaseModel):
    is_valid: bool
    total_records: int
    verified_records: int
    failed_records: int
    first_corrupted_seq: Optional[int] = None
    issues: List[VerificationIssue] = Field(default_factory=list)
    verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verification_time_ms: float = 0.0

class TamperRecordRequest(BaseModel):
    sequence_num: int
    tamper_field: str = "disposition" # or raw_text, ip, etc.
    new_value: str = "malicious_override"

class TamperRecordResponse(BaseModel):
    success: bool
    sequence_num: int
    event_id: str
    original_value: str
    tampered_value: str
    message: str
