"""
Strict OCSF 1.1.0 view of a stored event, used by every output connector.

TRACELOG stores a working record (OCSFEvent) with a few helper fields
(ISO time string, sequence number, raw_ref). Downstream tools expect the
schema exactly, so this module produces a spec-shaped event:

- ``time`` is epoch milliseconds (OCSF timestamp_t), ``type_uid`` is set,
- ``metadata`` carries version, product, uid (TRACELOG event id), sequence,
  original_time and the TRACELOG raw reference for lineage,
- ``connection_info`` always has its required ``direction_id``,
- Detection Findings carry the required ``finding_info.title`` / ``uid``,
- action / disposition use the security_control profile enums,
- IPs, hostnames and user names are listed as ``observables``.

Required attributes were checked against the official schema at
https://github.com/ocsf/ocsf-schema/tree/v1.1.0.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.config import settings

# The version every event is stamped with, and the one these rules were checked against. It is a
# setting (see backend/config.py and docs/adr/0001-ocsf-version.md); the required attributes of the
# four classes TRACELOG emits are unchanged across OCSF 1.1 to 1.3, so validate() is version-independent
# within that range.
OCSF_VERSION = settings.OCSF_VERSION
ACTION_IDS = {"allow": (1, "Allowed"), "deny": (2, "Denied"), "drop": (2, "Denied")}
DISPOSITION_IDS = {"allowed": (1, "Allowed"), "denied": (2, "Blocked"), "dropped": (6, "Dropped"),
                   "alert": (19, "Alert")}
STATUS_IDS = {"success": (1, "Success"), "failure": (2, "Failure")}
DIRECTION_IDS = {"inbound": (1, "Inbound"), "outbound": (2, "Outbound"), "lateral": (3, "Lateral")}
PROTOCOL_NUMS = {"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "ipv6-icmp": 58,
                 "sctp": 132}
OBS_HOSTNAME, OBS_IP, OBS_USER = (1, "Hostname"), (2, "IP Address"), (4, "User Name")
SECURITY_CONTROL_CLASSES = (4001, 2004)


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        out = {k: _prune(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    if isinstance(value, list):
        return [_prune(v) for v in value if v not in (None, "", {}, [])]
    return value


def _endpoint(ep: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not ep:
        return None
    return {"ip": ep.get("ip"), "port": ep.get("port"), "hostname": ep.get("hostname"), "mac": ep.get("mac")}


def to_ocsf(event: Dict[str, Any], include_raw: bool = True) -> Dict[str, Any]:
    """Convert a stored TRACELOG event (OCSFEvent dict) into a strict OCSF 1.1.0 event."""
    class_uid = int(event.get("class_uid", 0))
    activity_id = int(event.get("activity_id", 0))
    meta = event.get("metadata") or {}
    product = meta.get("product") or {}
    raw_ref = meta.get("raw_ref") or {}
    unmapped = dict(event.get("unmapped") or {})
    original_time = unmapped.pop("original_time", None)
    direction = str(unmapped.get("direction") or "").lower()

    out: Dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": event.get("class_name"),
        "category_uid": event.get("category_uid"),
        "category_name": event.get("category_name"),
        "activity_id": activity_id,
        "activity_name": event.get("activity_name"),
        "type_uid": class_uid * 100 + activity_id,
        "type_name": f"{event.get('class_name')}: {event.get('activity_name')}",
        "severity_id": event.get("severity_id", 0),
        "severity": event.get("severity"),
        "time": int(event.get("time_epoch_ms") or 0),
        "metadata": {
            "version": OCSF_VERSION,   # module attribute, so a test or a deployment can set it
            "uid": event.get("id"),
            "sequence": meta.get("sequence_num"),
            "original_time": str(original_time) if original_time else None,
            "processed_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "log_name": unmapped.get("parser_pack"),
            "product": {"vendor_name": product.get("vendor_name") or "Unknown", "name": product.get("name"),
                        "version": product.get("version")},
            "log_provider": "TRACELOG",
        },
        "message": unmapped.get("msg") or (event.get("finding") or {}).get("title"),
        "src_endpoint": _endpoint(event.get("src_endpoint")),
        "dst_endpoint": _endpoint(event.get("dst_endpoint")),
    }
    # TRACELOG lineage: link back to the preserved raw record and its hash.
    out["metadata"]["labels"] = [f"tracelog.raw_id={raw_ref.get('raw_id')}",
                                 f"tracelog.raw_sha256={raw_ref.get('raw_hash')}"] if raw_ref else None

    conn = event.get("connection_info") or {}
    if conn.get("protocol_name") or direction:
        pname = (conn.get("protocol_name") or "").lower() or None
        did, dname = DIRECTION_IDS.get(direction, (0, "Unknown"))
        out["connection_info"] = {"protocol_name": pname, "protocol_num": PROTOCOL_NUMS.get(pname or ""),
                                  "direction_id": did, "direction": dname}
    traffic = event.get("traffic") or {}
    if traffic:
        total = unmapped.get("bytes_total")
        out["traffic"] = {"bytes_in": traffic.get("bytes_in"), "bytes_out": traffic.get("bytes_out"),
                          "bytes": total if total is not None else (
                              (traffic.get("bytes_in") or 0) + (traffic.get("bytes_out") or 0) or None),
                          "packets": traffic.get("packets")}

    if class_uid in SECURITY_CONTROL_CLASSES:
        profiles = ["security_control"]
        aid = ACTION_IDS.get(str(event.get("action") or "").lower())
        if aid:
            out["action_id"], out["action"] = aid
        did = DISPOSITION_IDS.get(str(event.get("disposition") or "").lower())
        if did:
            out["disposition_id"], out["disposition"] = did
        out["metadata"]["profiles"] = profiles

    user = event.get("user") or {}
    if user.get("name"):
        out["user"] = {"name": user.get("name"), "domain": user.get("domain")}
    elif class_uid == 3002:
        out["user"] = {"name": "unknown"}  # user is required for Authentication
    status = STATUS_IDS.get(str(event.get("status") or "").lower())
    if status:
        out["status_id"], out["status"] = status

    if class_uid == 2004:
        finding = event.get("finding") or {}
        out["finding_info"] = {
            "title": finding.get("title") or event.get("activity_name") or "Detection",
            "uid": str(finding.get("uid") or event.get("id")),
            "types": finding.get("types") or None,
        }

    observables: List[Dict[str, Any]] = []
    for name, ep in (("src_endpoint", out.get("src_endpoint")), ("dst_endpoint", out.get("dst_endpoint"))):
        if ep and ep.get("ip"):
            observables.append({"name": f"{name}.ip", "type_id": OBS_IP[0], "type": OBS_IP[1], "value": ep["ip"]})
        if ep and ep.get("hostname"):
            observables.append({"name": f"{name}.hostname", "type_id": OBS_HOSTNAME[0], "type": OBS_HOSTNAME[1],
                                "value": ep["hostname"]})
    if out.get("user", {}).get("name") and out["user"]["name"] != "unknown":
        observables.append({"name": "user.name", "type_id": OBS_USER[0], "type": OBS_USER[1],
                            "value": out["user"]["name"]})
    out["observables"] = observables or None

    if include_raw:
        out["raw_data"] = event.get("raw_data")
    out["unmapped"] = unmapped or None
    result = _prune(out)
    if class_uid == 4001:  # both endpoints are required; an empty object means "not reported by the device"
        result.setdefault("src_endpoint", {})
        result.setdefault("dst_endpoint", {})
    return result


REQUIRED_BY_CLASS = {4001: ("src_endpoint", "dst_endpoint"), 3002: ("user",), 2004: ("finding_info",)}
BASE_REQUIRED = ("activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid")


def validate(ocsf: Dict[str, Any]) -> List[str]:
    """Return a list of OCSF 1.1.0 violations (empty when the event is valid for its class)."""
    problems = [f"missing {k}" for k in BASE_REQUIRED if k not in ocsf]
    meta = ocsf.get("metadata") or {}
    if not meta.get("version"):
        problems.append("missing metadata.version")
    if not (meta.get("product") or {}).get("vendor_name"):
        problems.append("missing metadata.product.vendor_name")
    if not isinstance(ocsf.get("time"), int):
        problems.append("time must be epoch milliseconds (int)")
    if ocsf.get("type_uid") != ocsf.get("class_uid", 0) * 100 + ocsf.get("activity_id", 0):
        problems.append("type_uid must equal class_uid * 100 + activity_id")
    for k in REQUIRED_BY_CLASS.get(ocsf.get("class_uid"), ()):
        if k not in ocsf:
            problems.append(f"missing {k} (required for class {ocsf.get('class_uid')})")
    if ocsf.get("class_uid") == 2004:
        fi = ocsf.get("finding_info") or {}
        problems += [f"missing finding_info.{k}" for k in ("title", "uid") if not fi.get(k)]
    if "connection_info" in ocsf and "direction_id" not in ocsf["connection_info"]:
        problems.append("missing connection_info.direction_id")
    for ob in ocsf.get("observables") or []:
        if "name" not in ob or "type_id" not in ob:
            problems.append("observable missing name/type_id")
    return problems


def event_time_seconds(ocsf: Dict[str, Any]) -> float:
    return (ocsf.get("time") or 0) / 1000.0
