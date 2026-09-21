from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

class ProductMetadata(BaseModel):
    vendor_name: str = "Unknown"
    name: str = "Unknown"
    version: Optional[str] = None

class RawRef(BaseModel):
    raw_id: str
    raw_hash: str

class Metadata(BaseModel):
    version: str = "1.1.0"
    product: ProductMetadata = Field(default_factory=ProductMetadata)
    sequence_num: int = 0
    raw_ref: RawRef

class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None

class ConnectionInfo(BaseModel):
    protocol_name: Optional[str] = None
    protocol_num: Optional[int] = None
    direction: Optional[str] = None # inbound, outbound, internal

class Traffic(BaseModel):
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    packets: Optional[int] = None

class User(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    type: Optional[str] = None

class Finding(BaseModel):
    title: Optional[str] = None
    desc: Optional[str] = None
    uid: Optional[str] = None
    types: List[str] = Field(default_factory=list)

class OCSFEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    class_uid: int = 4001 # 4001: Network Activity, 3001: Authentication, 2001: Security Finding
    class_name: str = "Network Activity"
    category_uid: int = 4 # 4: Network, 3: IAM, 2: Findings
    category_name: str = "Network Activity"
    activity_id: int = 1 # 1: Traffic, 2: Logon, 3: Detection
    activity_name: str = "Traffic"
    severity_id: int = 1 # 1: Info, 2: Low, 3: Medium, 4: High, 5: Critical
    severity: str = "Informational"
    time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    time_epoch_ms: int = Field(default_factory=lambda: int(datetime.utcnow().timestamp() * 1000))
    
    # Endpoints & network
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    connection_info: Optional[ConnectionInfo] = None
    traffic: Optional[Traffic] = None
    disposition: Optional[str] = None # allowed, denied, dropped, blocked, alert
    action: Optional[str] = None # allow, deny, drop, block, alert
    
    # IAM
    user: Optional[User] = None
    status: Optional[str] = None # success, failure
    logon_type: Optional[str] = None
    
    # Finding
    finding: Optional[Finding] = None
    
    # Preservation & Lineage
    metadata: Metadata
    raw_data: str
    unmapped: Dict[str, Any] = Field(default_factory=dict)

class RawLogRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    raw_text: str
    raw_hash: str
    ingested_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    format_detected: str = "unknown"
    status: str = "ingested" # ingested, parsed, failed
    error_message: Optional[str] = None
