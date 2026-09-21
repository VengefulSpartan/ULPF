import json
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from backend.models.correlation import IncidentSummary
from backend.services.correlation.engine import CorrelationEngine
from backend.services.storage.db import db

router = APIRouter(prefix="/correlation", tags=["Cross-Source RCA"])

class RunCorrelationRequest(BaseModel):
    pivot_ip: Optional[str] = None
    time_window_minutes: int = 60

@router.post("/run", response_model=IncidentSummary)
def run_rca(req: RunCorrelationRequest):
    try:
        incident = CorrelationEngine.run_correlation(
            pivot_ip=req.pivot_ip,
            time_window_minutes=req.time_window_minutes
        )
        return incident
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/incidents")
def list_incidents():
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            data = json.loads(r["data_json"])
            result.append(data)
        return result

@router.get("/incidents/{incident_id}", response_model=IncidentSummary)
def get_incident(incident_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Incident not found")
        return json.loads(r["data_json"])
