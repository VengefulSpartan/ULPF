import json
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from backend.models.parser import ParserCandidate, ParserValidationResult
from backend.services.storage.db import db
from backend.services.parser_generation.generator import ParserGenerator
from backend.services.parser_generation.tester import ParserTester

router = APIRouter(prefix="/parsers", tags=["Parser Studio & Zero-Touch Generation"])

class GenerateParserRequest(BaseModel):
    name: str
    vendor: str
    product: str
    target_ocsf_class: int = 4001
    sample_logs: List[str]

class TestParserRequest(BaseModel):
    sample_logs: List[str]

def _rule_view(r) -> dict:
    """A learned parser's spec shown as the rule model the registry lists (its fields as mappings)."""
    rule = json.loads(r["rule_json"])
    if r["format_type"] != "learned":
        return rule
    return {"format_type": "learned", "delimiter": rule.get("delimiter"),
            "mappings": [{"source_field": s["label"], "target_field": s["role"]}
                         for s in rule.get("slots", []) if s.get("role")]}


@router.get("", response_model=List[ParserCandidate])
def list_parsers():
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM parsers ORDER BY created_at DESC")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            rule_dict = _rule_view(r)
            val_dict = json.loads(r["validation_json"]) if r["validation_json"] else None
            result.append(ParserCandidate(
                id=r["id"],
                name=r["name"],
                vendor=r["vendor"],
                product=r["product"],
                format_type=r["format_type"],
                description=r["description"] or "",
                target_ocsf_class=r["target_ocsf_class"],
                rule=rule_dict,
                status=r["status"],
                created_at=r["created_at"],
                updated_at=r["updated_at"],
                validation=val_dict,
                tested=bool(r["tested"]),
                approved_by=r["approved_by"],
                approved_at=r["approved_at"]
            ))
        return result

@router.post("/generate", response_model=ParserCandidate, status_code=status.HTTP_201_CREATED)
def generate_parser(req: GenerateParserRequest):
    try:
        candidate = ParserGenerator.generate_candidate(
            sample_logs=req.sample_logs,
            name=req.name,
            vendor=req.vendor,
            product=req.product,
            target_ocsf_class=req.target_ocsf_class
        )
        
        # Save candidate to DB
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO parsers (
                    id, name, vendor, product, format_type, description, target_ocsf_class,
                    rule_json, status, created_at, updated_at, tested
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?, 0)
                """,
                (
                    candidate.id, candidate.name, candidate.vendor, candidate.product,
                    candidate.format_type, candidate.description, candidate.target_ocsf_class,
                    json.dumps(candidate.rule.model_dump()), candidate.created_at, candidate.updated_at
                )
            )
            conn.commit()
        return candidate
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{parser_id}/test", response_model=ParserCandidate)
def test_parser(parser_id: str, req: TestParserRequest):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM parsers WHERE id = ?", (parser_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Parser not found")

        if r["format_type"] == "learned":
            raise HTTPException(status_code=400, detail="Learned parsers are re-tested with PUT /api/formats/parsers/"
                                                        f"{parser_id}")
        rule_dict = json.loads(r["rule_json"])
        candidate = ParserCandidate(
            id=r["id"],
            name=r["name"],
            vendor=r["vendor"],
            product=r["product"],
            format_type=r["format_type"],
            description=r["description"] or "",
            target_ocsf_class=r["target_ocsf_class"],
            rule=rule_dict,
            status=r["status"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            tested=bool(r["tested"])
        )

        tested_candidate = ParserTester.test_candidate(candidate, req.sample_logs)

        # Update in DB
        cursor.execute(
            """
            UPDATE parsers 
            SET validation_json = ?, tested = 1, updated_at = datetime('now')
            WHERE id = ?
            """,
            (json.dumps(tested_candidate.validation.model_dump()), parser_id)
        )
        conn.commit()

        return tested_candidate

@router.post("/{parser_id}/approve", response_model=ParserCandidate)
def approve_parser(parser_id: str):
    """
    Approve Gate: Never silently approve an untested parser!
    """
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM parsers WHERE id = ?", (parser_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Parser not found")

        if r["format_type"] == "learned":
            raise HTTPException(
                status_code=400,
                detail="Learned parsers are approved from Parser Studio's New log formats tab "
                       f"(POST /api/formats/parsers/{parser_id}/approve), where fields that rest on position "
                       "alone must be confirmed by name."
            )
        if not bool(r["tested"]):
            raise HTTPException(
                status_code=400,
                detail="Approval rejected: Candidate parser must pass test validation against sample logs before approval."
            )

        val_json = r["validation_json"]
        if val_json:
            val_data = json.loads(val_json)
            if val_data.get("passed_samples", 0) == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Approval rejected: Parser failed on all test samples. Fix rules before approval."
                )

        now_str = datetime.utcnow().isoformat()
        cursor.execute(
            """
            UPDATE parsers 
            SET status = 'approved', approved_by = 'security_engineer', approved_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (now_str, now_str, parser_id)
        )
        conn.commit()

        # Re-fetch
        cursor.execute("SELECT * FROM parsers WHERE id = ?", (parser_id,))
        up = cursor.fetchone()
        return ParserCandidate(
            id=up["id"],
            name=up["name"],
            vendor=up["vendor"],
            product=up["product"],
            format_type=up["format_type"],
            description=up["description"] or "",
            target_ocsf_class=up["target_ocsf_class"],
            rule=json.loads(up["rule_json"]),
            status=up["status"],
            created_at=up["created_at"],
            updated_at=up["updated_at"],
            validation=json.loads(up["validation_json"]) if up["validation_json"] else None,
            tested=bool(up["tested"]),
            approved_by=up["approved_by"],
            approved_at=up["approved_at"]
        )

@router.post("/{parser_id}/reject", response_model=ParserCandidate)
def reject_parser(parser_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        r = cursor.execute("SELECT format_type FROM parsers WHERE id = ?", (parser_id,)).fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Parser not found")
        if r["format_type"] == "learned":
            from backend.services.parser_generation.workflow import reject
            reject(parser_id)
        cursor.execute("UPDATE parsers SET status = 'rejected', updated_at = datetime('now') WHERE id = ?", (parser_id,))
        conn.commit()
        cursor.execute("SELECT * FROM parsers WHERE id = ?", (parser_id,))
        up = cursor.fetchone()
        return ParserCandidate(
            id=up["id"],
            name=up["name"],
            vendor=up["vendor"],
            product=up["product"],
            format_type=up["format_type"],
            description=up["description"] or "",
            target_ocsf_class=up["target_ocsf_class"],
            rule=_rule_view(up),
            status=up["status"],
            created_at=up["created_at"],
            updated_at=up["updated_at"],
            validation=json.loads(up["validation_json"]) if up["validation_json"] else None,
            tested=bool(up["tested"])
        )
