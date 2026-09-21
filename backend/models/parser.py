from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

class FieldMapping(BaseModel):
    source_field: str
    target_field: str # dot-notation, e.g. "src_endpoint.ip", "severity_id"
    transform: Optional[str] = None # int, lower, ip, epoch, iso8601

class ParserRule(BaseModel):
    format_type: str # cef, leef, syslog, kv, json, regex
    regex_pattern: Optional[str] = None
    delimiter: Optional[str] = None
    kv_delimiter: Optional[str] = None
    mappings: List[FieldMapping] = Field(default_factory=list)

class ParserTestCase(BaseModel):
    sample_log: str
    expected_matches: Optional[Dict[str, Any]] = None
    passed: Optional[bool] = None
    extracted_fields: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class ParserValidationResult(BaseModel):
    total_samples: int = 0
    passed_samples: int = 0
    failed_samples: int = 0
    accuracy_score: float = 0.0
    sample_results: List[ParserTestCase] = Field(default_factory=list)
    unmapped_fields: List[str] = Field(default_factory=list)
    validation_errors: List[str] = Field(default_factory=list)

class ParserBase(BaseModel):
    name: str
    vendor: str
    product: str
    format_type: str
    description: Optional[str] = ""
    target_ocsf_class: int = 4001
    rule: ParserRule

class ParserCandidate(ParserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "candidate" # candidate, approved, rejected
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    validation: Optional[ParserValidationResult] = None
    tested: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
