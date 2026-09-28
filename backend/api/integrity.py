from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from backend.services.integrity import checkpoints
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


# ---------------------------------------------------------------------------------- signed checkpoints
class RewriteRequest(BaseModel):
    sequence_num: int
    field: str = "disposition"
    new_value: str = "allowed"


@router.get("/checkpoints")
def verify_checkpoints(witnesses: bool = True):
    """Recompute every signed checkpoint from the records as they are now, check the node's and the
    witnesses' signatures, and compare with what each witness says it signed."""
    return checkpoints.verify(ask_witnesses=witnesses)


@router.get("/proof/{sequence_num}")
def inclusion_proof(sequence_num: int):
    """The Merkle inclusion proof of one record in the signed checkpoint that covers it."""
    p = checkpoints.proof(sequence_num)
    if p is None:
        raise HTTPException(status_code=404, detail=f"record #{sequence_num} is not in a signed checkpoint yet")
    return p


@router.post("/checkpoints/seal")
def seal_checkpoints():
    """Seal every record not yet in a checkpoint now, and send the new checkpoints to the witnesses."""
    try:
        made = checkpoints.seal(force=True)
    except (checkpoints.RewriteActive, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    witnesses = checkpoints.cosign_pending()
    return {"sealed": [{"index": m["idx"], "first_seq": m["first_seq"], "last_seq": m["last_seq"]} for m in made],
            "witnesses": witnesses}


@router.post("/rewrite")
def rewrite_history(req: RewriteRequest):
    """Demonstration: change a record, recompute the chain after it and re-sign the checkpoints, as an
    insider with the database and the node's keys could. Only the witnesses still hold the original."""
    try:
        result = checkpoints.rewrite_history(req.sequence_num, req.field, req.new_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result["witnesses"] = checkpoints.cosign_pending()   # what the witnesses say to the rewritten checkpoints
    return result


@router.post("/rewrite/restore")
def restore_history():
    try:
        return checkpoints.restore_history()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
