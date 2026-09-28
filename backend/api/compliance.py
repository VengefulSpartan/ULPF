"""CERT-In mode: retention status and incident report drafts (backend/services/compliance/certin.py)."""
import json
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.services.compliance import certin

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/certin/status")
def certin_status():
    """Whether CERT-In mode is on, how many days of logs the archive holds, and the incident types."""
    return {**certin.retention_status(), "incident_types": certin.INCIDENT_TYPES, "report_to": certin.REPORT_TO,
            "report_within_hours": certin.REPORT_WITHIN.total_seconds() / 3600}


def _draft(incident_id: str, noticed_at: Optional[str], types: Optional[List[str]], **org):
    try:
        return certin.draft_report(incident_id, org=org, noticed_at=noticed_at, types=types)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


_ORG = ("organisation", "sector", "address", "contact_name", "designation", "phone", "email")


@router.get("/certin/report.json")
def certin_report_json(incident_id: str, noticed_at: Optional[str] = None, types: Optional[List[str]] = Query(None),
                       organisation: str = "", sector: str = "", address: str = "", contact_name: str = "",
                       designation: str = "", phone: str = "", email: str = ""):
    """A draft of the facts a CERT-In incident report needs, from a stored correlation result."""
    r = _draft(incident_id, noticed_at, types, organisation=organisation, sector=sector, address=address,
               contact_name=contact_name, designation=designation, phone=phone, email=email)
    return Response(json.dumps(r, indent=2, ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{r["report_id"]}.json"'})


@router.get("/certin/report.pdf")
def certin_report_pdf(incident_id: str, noticed_at: Optional[str] = None, types: Optional[List[str]] = Query(None),
                      organisation: str = "", sector: str = "", address: str = "", contact_name: str = "",
                      designation: str = "", phone: str = "", email: str = ""):
    from backend.services.compliance.certin_pdf import render_report
    r = _draft(incident_id, noticed_at, types, organisation=organisation, sector=sector, address=address,
               contact_name=contact_name, designation=designation, phone=phone, email=email)
    return Response(render_report(r), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{r["report_id"]}.pdf"'})
