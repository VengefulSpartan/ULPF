"""Evidence bundles: chosen records, their proofs and a checker, as one ZIP (backend/services/evidence/bundle.py)."""
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.services.evidence import bundle

router = APIRouter(prefix="/evidence", tags=["Evidence"])


def _sequences(seq: Optional[List[int]], incident_id: Optional[str]):
    if incident_id:
        found = bundle.incident_sequences(incident_id)
        return found["sequences"], {"kind": "incident", "incident_id": incident_id, "title": found["title"]}
    return seq or [], {"kind": "records"}


@router.get("/bundle.zip")
def evidence_bundle(seq: Optional[List[int]] = Query(None, description="chain sequence numbers; repeat the parameter"),
                    incident_id: Optional[str] = None, case_ref: str = "", prepared_by: str = "",
                    designation: str = "", organisation: str = "", place: str = ""):
    """A ZIP with the raw lines, stored events, chain records, Merkle proofs, signed checkpoints, a
    standard-library verify.py and the Section 63(4) certificate particulars with the hash report."""
    try:
        sequences, scope = _sequences(seq, incident_id)
        made = bundle.build(sequences, case={"case_ref": case_ref, "prepared_by": prepared_by,
                                             "designation": designation, "organisation": organisation,
                                             "place": place}, scope=scope)
    except bundle.EvidenceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(made["zip"], media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{made["filename"]}"',
                             "X-Evidence-Bundle": made["id"], "X-Manifest-SHA256": made["manifest_sha256"]})
