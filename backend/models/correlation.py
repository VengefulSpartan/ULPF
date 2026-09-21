from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

class ObservedFact(BaseModel):
    event_id: str
    sequence_num: int
    timestamp: str
    source_vendor: str
    source_product: str
    event_class: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    severity: str
    raw_hash: str
    fact_description: str

class InferredRelationship(BaseModel):
    inference_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_event_ids: List[str]
    relationship_type: str # e.g. TEMPORAL_PIVOT, CREDENTIAL_PIVOT, RECON_TO_EXPLOIT, LATERAL_MOVEMENT
    confidence: float # 0.0 to 1.0 (e.g. 0.85)
    time_delta_seconds: float
    hypothesis: str
    rationale: str

class IncidentSummary(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: str # Critical, High, Medium, Low
    confidence_score: float
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    start_time: str
    end_time: str
    entities: Dict[str, List[str]] # {"ips": [...], "users": [...], "devices": [...]}
    observed_facts: List[ObservedFact] = Field(default_factory=list)
    inferred_relationships: List[InferredRelationship] = Field(default_factory=list)
    attack_phases: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
