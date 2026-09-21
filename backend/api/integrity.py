from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from backend.services.integrity.ledger import IntegrityLedger
from backend.models.integrity import (
    IntegrityVerificationResult, TamperRecordRequest, TamperRecordResponse
)
from backend.services.storage.db import db

router = APIRouter(prefix="/integrity", tags=["Chain-of-Custody Integrity"])

class RestoreRecordRequest(BaseModel):
    sequence_num: int

@router.get("/verify", response_model=IntegrityVerificationResult)
def verify_hash_chain():
    """
    Exhaustive cryptographic audit across the entire chain-of-custody ledger.
    """
    return IntegrityLedger.verify_chain()

@router.get("/ledger")
def get_ledger(limit: int = Query(50, ge=1, le=200)):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT l.*, n.severity, n.class_name, n.action
            FROM integrity_ledger l
            LEFT JOIN normalized_events n ON l.event_id = n.id
            ORDER BY l.sequence_num DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

@router.post("/tamper", response_model=TamperRecordResponse)
def simulate_tampering(req: TamperRecordRequest):
    """
    Demonstrates controlled tampering: alters a record in SQLite to trigger verification failure.
    """
    try:
        res = IntegrityLedger.simulate_tampering(
            sequence_num=req.sequence_num,
            field=req.tamper_field,
            new_value=req.new_value
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/restore")
def restore_tampered_record(req: RestoreRecordRequest):
    """
    Restores the tampered record back to its verified original state.
    """
    restored = IntegrityLedger.restore_tampered_record(req.sequence_num)
    if not restored:
        raise HTTPException(status_code=404, detail="No backup record found to restore for this sequence number")
    return {"success": True, "message": f"Successfully restored sequence #{req.sequence_num} to original state."}
