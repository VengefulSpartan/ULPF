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
    """A correlation rule that held, with the evidence that made it hold. Deliberately no
    confidence score: nothing measures one (see backend/services/correlation/engine.py)."""
    inference_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_event_ids: List[str]
    relationship_type: str  # LOGIN_THEN_ACTIVITY, ALLOWED_THEN_ALERT, PORT_SWEEP
    time_delta_seconds: float
    shared_entities: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    hypothesis: str
    rationale: str

class IncidentSummary(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: str  # the highest severity among the observed facts
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    start_time: str
    end_time: str
    entities: Dict[str, List[str]] # {"ips": [...], "users": [...], "devices": [...]}
    observed_facts: List[ObservedFact] = Field(default_factory=list)
    inferred_relationships: List[InferredRelationship] = Field(default_factory=list)
    attack_phases: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
