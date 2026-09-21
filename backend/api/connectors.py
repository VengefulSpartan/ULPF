import json
import time
import uuid

from fastapi import APIRouter, HTTPException

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
