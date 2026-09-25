"""
TRACELOG's own baseline detector (backend/services/ml/baseline.py) writes each flag as one JSON line
and sends it through the same writer as any device's log. This pack reads that line back into an
OCSF Detection Finding, so a flag is archived byte for byte, hash-chained, delivered to the outputs
and traceable like an IDS alert.

The line's schema is TRACELOG's own and fixed ("tracelog_detector": "baseline", "version": 1), so
the pack reads it exactly; everything in it (each reason, its baseline, the evidence event ids) is
kept under unmapped.vendor_fields.

Where a flag came from is in the event too: the detector writes with transport "internal", so a
line that merely imitates the format but arrived over syslog or HTTP shows that transport and its
sender's address.
"""
import json
from typing import Optional

from .common import DETECTION_FINDING, event
from .envelope import Envelope

NAME = "tracelog_baseline"
VENDOR, PRODUCT = "TRACELOG", "Baseline detector"
MARKER = '"tracelog_detector":"baseline"'


def detect(env: Envelope) -> bool:
    return MARKER in env.message


def parse(env: Envelope) -> Optional[dict]:
    try:
        obj = json.loads(env.message)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("tracelog_detector") != "baseline" or obj.get("version") != 1:
        return None
    entity_type, entity = obj.get("entity_type"), obj.get("entity")
    return event(VENDOR, PRODUCT, DETECTION_FINDING, 1, "Create", vendor_fields=obj,
                 signature=obj.get("title"), rule_id=obj.get("finding_uid"), severity=obj.get("severity"),
                 timestamp=obj.get("time"), msg=obj.get("summary"),
                 src_ip=entity if entity_type == "src_ip" else None,
                 user=entity if entity_type == "user" else None,
                 threat_type="baseline anomaly")
