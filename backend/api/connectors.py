import json
import time
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from backend.connectors.engine import engine
from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.storage.db import db

router = APIRouter(prefix="/connectors", tags=["Connectors"])


@router.get("")
def connector_status():
    """Live status of every input and output, plus the supported sources and destinations."""
    return engine.status()


def _sample_event() -> dict:
    with db.get_connection() as conn:
        row = conn.execute("SELECT normalized_json FROM normalized_events ORDER BY sequence_num DESC LIMIT 1").fetchone()
    if row:
        ev = to_ocsf(json.loads(row["normalized_json"]))
    else:
        now = int(time.time() * 1000)
        ev = {"class_uid": 4001, "class_name": "Network Activity", "category_uid": 4,
              "category_name": "Network Activity", "activity_id": 6, "activity_name": "Traffic",
              "type_uid": 400106, "severity_id": 1, "severity": "Informational", "time": now,
              "metadata": {"version": "1.1.0", "uid": str(uuid.uuid4()),
                           "product": {"vendor_name": "TRACELOG", "name": "connector test"}},
              "src_endpoint": {"ip": "192.0.2.10", "port": 51000}, "dst_endpoint": {"ip": "198.51.100.20", "port": 443},
              "message": "TRACELOG connector test event"}
    ev.setdefault("unmapped", {})["tracelog_test_event"] = True
    return ev


@router.post("/outputs/{name}/test")
def test_output(name: str):
    """Send one event synchronously to an output and report whether it was accepted."""
    for sink in engine.sinks:
        if sink.cfg.name == name:
            sample = _sample_event()
            result = sink.test(sample)
            return {**result, "output": name, "type": sink.type_name, "ocsf_violations": validate(sample)}
    raise HTTPException(status_code=404, detail=f"No running output named '{name}'")


@router.post("/flush")
def flush(timeout: float = 10.0):
    """Wait until everything received has been stored and handed to the outputs (useful for demos and tests)."""
    return {"drained": engine.flush(timeout=timeout), "status": engine.status()["pipeline"]}


# ---- dead letters ---------------------------------------------------------------------------
@router.get("/dead-letters")
def list_dead_letters():
    """Every output's undelivered events: how many, of which kind, why, from which devices."""
    return engine.dead_letters()


@router.get("/dead-letters/{name}")
def dead_letter_entries(name: str, limit: int = Query(20, ge=1, le=500)):
    """The most recent dead-letter entries for one output, with the full OCSF event and the reason."""
    stores = engine.dead_letter_stores()
    if name not in stores:
        raise HTTPException(status_code=404, detail=f"no dead letters for '{name}'")
    return {"summary": stores[name].summary(), "entries": stores[name].latest(limit)}


@router.post("/dead-letters/{name}/replay")
def replay_dead_letters(name: str,
                        to: Optional[str] = Query(None, description="send through this output instead"),
                        kinds: Optional[str] = Query(None, description="comma-separated: undeliverable,"
                                                                        "queue_full,rejected (default: all)"),
                        limit: Optional[int] = Query(None, ge=1, description="stop after this many events"),
                        wait: float = Query(30.0, ge=0, le=300, description="seconds to wait for the result")):
    """
    Re-send dead letters. Runs in the delivering output's own thread between live batches. Stops at
    the first batch the destination does not accept and keeps everything not delivered; call again
    once the cause is fixed. Returns the replay's progress (state: done, stopped, limit_reached, running).
    """
    store = engine.dead_letter_stores().get(name)
    try:
        kind_list = [k.strip() for k in kinds.split(",") if k.strip()] if kinds else None
        progress = engine.replay_dead_letters(name, to=to, kinds=kind_list, limit=limit, wait=wait)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    remaining = store.summary()
    return {**progress, "remaining": remaining["waiting"], "remaining_by_kind": remaining["by_kind"]}
