from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field
import uuid

class SourceBase(BaseModel):
    name: str = Field(..., description="Unique name of the log source")
    vendor: str = Field(..., description="Vendor name, e.g. Cisco, Palo Alto, Fortinet, Suricata")
    product: str = Field(..., description="Product model, e.g. ASA, PAN-OS, FortiGate, EVE")
    format_type: str = Field(..., description="Expected format: syslog, cef, leef, json, kv, auto")
    category: str = Field(default="network", description="Category: firewall, router, vpn, ids, proxy")
    description: Optional[str] = ""
    is_active: bool = True

class SourceCreate(SourceBase):
    pass

class Source(SourceBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    event_count: int = 0
    last_event_at: Optional[str] = None
