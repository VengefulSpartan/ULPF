from fastapi import APIRouter, HTTPException, status
from typing import List
from backend.models.source import Source, SourceCreate
from backend.services.storage.db import db

router = APIRouter(prefix="/sources", tags=["Sources & Onboarding"])

@router.get("", response_model=List[Source])
def list_sources():
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sources ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [
            Source(
                id=r["id"],
                name=r["name"],
                vendor=r["vendor"],
                product=r["product"],
                format_type=r["format_type"],
                category=r["category"],
                description=r["description"] or "",
                is_active=bool(r["is_active"]),
                created_at=r["created_at"],
                event_count=r["event_count"],
                last_event_at=r["last_event_at"]
            )
            for r in rows
        ]

@router.post("", response_model=Source, status_code=status.HTTP_201_CREATED)
def create_source(source_in: SourceCreate):
    source = Source(**source_in.model_dump())
    with db.get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO sources (id, name, vendor, product, format_type, category, description, is_active, created_at, event_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    source.id, source.name, source.vendor, source.product,
                    source.format_type, source.category, source.description,
                    1 if source.is_active else 0, source.created_at
                )
            )
            conn.commit()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Source creation failed: {str(e)}")
    return source

@router.get("/{source_id}", response_model=Source)
def get_source(source_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Source not found")
        return Source(
            id=r["id"],
            name=r["name"],
            vendor=r["vendor"],
            product=r["product"],
            format_type=r["format_type"],
            category=r["category"],
            description=r["description"] or "",
            is_active=bool(r["is_active"]),
            created_at=r["created_at"],
            event_count=r["event_count"],
            last_event_at=r["last_event_at"]
        )

@router.delete("/{source_id}")
def delete_source(source_id: str):
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        conn.commit()
    return {"message": "Source deleted successfully"}
