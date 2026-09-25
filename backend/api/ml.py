"""
Analytics and machine-learning endpoints (docs/ML_DATA.md):

  GET  /api/ml/contract        the columns of the analytics row, with their types and meanings
  GET  /api/ml/features        per-entity 5-minute window features, as CSV or JSON
  POST /api/ml/baseline/run    score recent windows against their baseline and write the flags as
                               OCSF Detection Findings
"""
import io
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.services.ml import baseline, features as feat
from backend.services.ml.rows import COLUMNS

router = APIRouter(prefix="/ml", tags=["Analytics & ML"])


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


@router.get("/contract")
def contract():
    """The analytics row every Parquet file holds and the features are computed from."""
    return {"columns": [{"name": n, "type": t, "meaning": m} for n, t, m in COLUMNS],
            "rules": ["a null means the device did not say; nothing is filled in",
                      "time_source says whether the time is the device's or the arrival time",
                      "fields_verified is false when fields were inferred rather than read by a known parser",
                      "sequence_num, raw_id and raw_sha256 lead back to the archived line"]}


@router.get("/features")
def features(entity_type: str = Query("src_ip", pattern="^(src_ip|user|device)$"),
             hours: float = Query(24, gt=0, le=24 * 31), window_minutes: int = Query(5, ge=1, le=60),
             format: str = Query("csv", pattern="^(csv|json)$"), limit: int = Query(100_000, ge=1, le=1_000_000)):
    """Window features for the last `hours` of events, oldest window first."""
    until = _now_ms()
    events = feat.events_from_db(since_ms=until - int(hours * 3600 * 1000), until_ms=until)
    table = feat.window_features(events, entity_type, window_minutes).head(limit)
    if format == "json":
        rows = table.to_dict("records")
        return [{k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in r.items()} for r in rows]
    buf = io.StringIO()
    table.to_csv(buf, index=False)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=tracelog_features_{entity_type}.csv"})


@router.post("/baseline/run")
def run_baseline(hours: float = Query(1, gt=0, le=24 * 7), lookback_hours: float = Query(24, gt=0, le=24 * 31),
                 until: Optional[str] = Query(None, description="ISO 8601; default now"),
                 dry_run: bool = Query(False, description="report the flags without writing findings")):
    """Score the complete windows of the last `hours` against `lookback_hours` of history. Each flag
    is written once, as an OCSF Detection Finding, through the same writer as every log line."""
    until_ms = None
    if until:
        try:
            until_ms = int(datetime.fromisoformat(until.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"until is not an ISO 8601 time: {exc}")
    return baseline.run(until_ms=until_ms, score_hours=hours, lookback_hours=lookback_hours, write=not dry_run)
