"""
New log formats: what TRACELOG received that no parser knows, and turning that into an
approved parser (see services/parser_generation/workflow.py).
"""
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.services.parser_generation import workflow
from backend.services.parser_generation.reparse import reparse_history
from backend.services.parsing.formats import list_formats
from backend.services.storage import db as db_module

router = APIRouter(prefix="/formats", tags=["New log formats & learned parsers"])


class LearnRequest(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None


class EditRequest(BaseModel):
    roles: Dict[str, Optional[str]] = Field(default_factory=dict,
                                            description="slot id -> field (src_ip, dst_port, ...) or null to clear")
    confirmed: List[str] = Field(default_factory=list, description="slot ids whose proposed field is confirmed")
    reviewer: str = "reviewer"
    name: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    class_uid: Optional[int] = None


class ApproveRequest(BaseModel):
    approved_by: str
    confirmed: List[str] = Field(default_factory=list)


class ReparseRequest(BaseModel):
    reason: Optional[str] = None
    limit: Optional[int] = None


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except workflow.WorkflowError as exc:
        raise HTTPException(status_code=exc.status, detail={"message": str(exc), **exc.detail}
                            if exc.detail else str(exc))


@router.get("")
def formats(status: Optional[str] = Query(None, description="new | learned | ignored")):
    with db_module.db.get_connection() as conn:
        return list_formats(conn, status)


@router.get("/parsers/{parser_id}")
def learned_parser(parser_id: str):
    return _call(workflow.candidate, parser_id)


@router.put("/parsers/{parser_id}")
def edit_parser(parser_id: str, req: EditRequest):
    return _call(workflow.edit, parser_id, req.roles, req.confirmed, req.reviewer, req.name, req.vendor, req.product,
                 req.class_uid)


@router.post("/parsers/{parser_id}/approve")
def approve_parser(parser_id: str, req: ApproveRequest):
    return _call(workflow.approve, parser_id, req.approved_by, req.confirmed)


@router.post("/parsers/{parser_id}/reject")
def reject_parser(parser_id: str):
    return _call(workflow.reject, parser_id)


@router.post("/parsers/{parser_id}/reparse")
def reparse(parser_id: str, req: Optional[ReparseRequest] = None):
    req = req or ReparseRequest()
    try:
        return reparse_history(parser_id, req.reason, req.limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{format_id}")
def format_detail(format_id: str, samples: int = Query(20, ge=1, le=200)):
    return _call(workflow.format_detail, format_id, samples)


@router.post("/{format_id}/learn")
def learn(format_id: str, req: Optional[LearnRequest] = None):
    req = req or LearnRequest()
    return _call(workflow.learn_format, format_id, req.name, req.vendor, req.product)


@router.post("/{format_id}/ignore")
def ignore(format_id: str, undo: bool = False):
    return _call(workflow.set_ignored, format_id, not undo)
