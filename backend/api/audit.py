"""Reconciliation and audit report: proof that every stored log line is accounted for at every output."""
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.services.integrity.delivery_ledger import DeliveryLedger
from backend.services.integrity.reconcile import audit_report, reconcile

router = APIRouter(prefix="/audit", tags=["Audit & Reconciliation"])


@router.get("/reconcile")
def get_reconciliation(verify: bool = True):
    """Archive = normalised = hash chain, and per output: owed = delivered + filtered + waiting + in flight."""
    return reconcile(verify=verify)


@router.get("/delivery/verify")
def verify_delivery_ledger():
    """Recompute the delivery ledger's hash chain and every batch's event list."""
    return DeliveryLedger.verify()


@router.get("/report.json")
def audit_report_json():
    r = audit_report()
    return Response(json.dumps(r, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="tracelog-audit-{r["report_id"]}.json"'})


@router.get("/report.pdf")
def audit_report_pdf():
    try:
        from backend.services.integrity.audit_pdf import render_pdf
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export needs reportlab: pip install reportlab "
                                                    "(the JSON report works without it)")
    r = audit_report()
    return Response(render_pdf(r), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="tracelog-audit-{r["report_id"]}.pdf"'})
