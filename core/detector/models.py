from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class DetectionResult(BaseModel):
    """Result of log format fingerprint classification."""
    format: str = Field(description="Detected format (cef, leef, json, xml, kv, csv, syslog_rfc5424, syslog_rfc3164, unknown)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    details: Dict[str, Any] = Field(default_factory=dict, description="Extracted format details or header metadata")
    fingerprint_rule: str = Field(default="none", description="Name of matching fingerprint rule")
