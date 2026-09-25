"""
The data contract for analytics and machine learning: one flat row per OCSF event.

The Parquet output writes these rows, and the feature export builds its windows from them, so a
model trained on a data-lake file and a feature computed inside TRACELOG read the same values.

Two rules, the same ones the parsers follow:

- A null means the device did not say. Nothing is filled in: a firewall that does not report bytes
  has null bytes, not 0, and an event whose time the device did not give is marked
  time_source="received" instead of passing the arrival time off as the event's time.
- Every row says where its values came from (`parser`, `fields_verified`) and how to get back to
  the line the device sent (`sequence_num`, `raw_id`, `raw_sha256`), so a model's input can be
  filtered to verified fields and any row a model flags can be traced to its bytes.

The column list below is the contract; docs/ML_DATA.md describes each column for people.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# (column, Arrow type, meaning). Existing columns keep their names and meanings; new ones are added.
COLUMNS: List[Tuple[str, str, str]] = [
    ("time", "int64", "event time, epoch milliseconds UTC"),
    ("event_time", "string", "the same time as ISO 8601"),
    ("time_source", "string", "'device' when the device gave the time, 'received' when it did not"),
    ("class_uid", "int32", "OCSF class: 4001 Network Activity, 3002 Authentication, 2004 Detection Finding, 0 Base"),
    ("class_name", "string", "OCSF class name"),
    ("activity_id", "int32", "OCSF activity id within the class"),
    ("activity_name", "string", "OCSF activity name"),
    ("severity_id", "int32", "OCSF severity id, 0-6"),
    ("severity", "string", "OCSF severity name"),
    ("status_id", "int32", "Authentication outcome: 1 success, 2 failure; null when the device gave none"),
    ("action_id", "int32", "OCSF action id: 1 allowed, 2 denied; null when the device gave none"),
    ("action", "string", "OCSF action name"),
    ("disposition_id", "int32", "OCSF disposition id (1 allowed, 2 blocked, 6 dropped, 19 alert)"),
    ("disposition", "string", "OCSF disposition name"),
    ("src_ip", "string", "source address"),
    ("src_port", "int32", "source port"),
    ("src_hostname", "string", "source name, when the device logged a name instead of an address"),
    ("dst_ip", "string", "destination address"),
    ("dst_port", "int32", "destination port"),
    ("dst_hostname", "string", "destination name, when the device logged a name instead of an address"),
    ("protocol", "string", "transport protocol name, lower case"),
    ("protocol_num", "int32", "IANA protocol number"),
    ("direction_id", "int32", "OCSF direction: 0 unknown, 1 inbound, 2 outbound, 3 lateral"),
    ("bytes_in", "int64", "bytes from destination to source, as the device reported"),
    ("bytes_out", "int64", "bytes from source to destination, as the device reported"),
    ("packets", "int64", "packets, as the device reported"),
    ("user_name", "string", "user name"),
    ("finding_title", "string", "Detection Finding title (signature, rule name)"),
    ("finding_uid", "string", "Detection Finding id (signature or rule id)"),
    ("vendor", "string", "device vendor"),
    ("product", "string", "device product"),
    ("device_hostname", "string", "the device that logged the event, by the hostname in its log"),
    ("sender_ip", "string", "the address the line arrived from (the device, or a relay)"),
    ("parser", "string", "what read the line: a vendor pack's name, 'learned', 'generic_cef' / 'generic_leef', "
                         "or 'generic_inferred'"),
    ("fields_verified", "bool", "true when a parser that knows the format read the fields (vendor pack, "
                                "approved learned parser, CEF/LEEF); false when they were inferred from evidence"),
    ("sequence_num", "int64", "position in the event hash chain"),
    ("event_uid", "string", "TRACELOG event id"),
    ("raw_id", "string", "id of the archived raw line"),
    ("raw_sha256", "string", "SHA-256 of the bytes received"),
    ("ocsf", "string", "the whole OCSF event as JSON"),
]
NAMES = [name for name, _, _ in COLUMNS]


def _label(meta: Dict[str, Any], key: str) -> Optional[str]:
    prefix = f"tracelog.{key}="
    for label in meta.get("labels") or []:
        if isinstance(label, str) and label.startswith(prefix):
            return label[len(prefix):] or None
    return None


def fields_verified(unmapped: Dict[str, Any]) -> bool:
    """True when the event's fields were read by a parser that knows the format."""
    tp = unmapped.get("tracelog_parse")
    if isinstance(tp, dict) and "verified" in tp:
        return bool(tp["verified"])        # generic inference and CSV headers: False; learned, CEF/LEEF: True
    # vendor packs do not add tracelog_parse; a line whose parser raised has no pack at all
    return bool(unmapped.get("parser_pack")) and "parse_error" not in unmapped


def _iso(ms: Any) -> str:
    """The same text the outputs write for an event's time (connectors/outputs/formats.ts_iso)."""
    return datetime.fromtimestamp((ms or 0) / 1000.0, tz=timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def ml_row(e: Dict[str, Any], include_ocsf: bool = True) -> Dict[str, Any]:
    """The contract row for one strict OCSF event (the dict outputs receive, from ocsf_export.to_ocsf)."""
    meta = e.get("metadata") or {}
    prod = meta.get("product") or {}
    src, dst = e.get("src_endpoint") or {}, e.get("dst_endpoint") or {}
    conn = e.get("connection_info") or {}
    traffic = e.get("traffic") or {}
    unmapped = e.get("unmapped") or {}
    finding = e.get("finding_info") or {}
    row = {
        "time": e.get("time"), "event_time": _iso(e.get("time")),
        "time_source": unmapped.get("time_source") or "device",
        "class_uid": e.get("class_uid"), "class_name": e.get("class_name"),
        "activity_id": e.get("activity_id"), "activity_name": e.get("activity_name"),
        "severity_id": e.get("severity_id"), "severity": e.get("severity"),
        "status_id": e.get("status_id"),
        "action_id": e.get("action_id"), "action": e.get("action"),
        "disposition_id": e.get("disposition_id"), "disposition": e.get("disposition"),
        "src_ip": src.get("ip"), "src_port": src.get("port"), "src_hostname": src.get("hostname"),
        "dst_ip": dst.get("ip"), "dst_port": dst.get("port"), "dst_hostname": dst.get("hostname"),
        "protocol": conn.get("protocol_name"), "protocol_num": conn.get("protocol_num"),
        "direction_id": conn.get("direction_id"),
        "bytes_in": traffic.get("bytes_in"), "bytes_out": traffic.get("bytes_out"), "packets": traffic.get("packets"),
        "user_name": (e.get("user") or {}).get("name") if (e.get("user") or {}).get("name") != "unknown" else None,
        "finding_title": finding.get("title"), "finding_uid": finding.get("uid"),
        "vendor": prod.get("vendor_name"), "product": prod.get("name"),
        "device_hostname": unmapped.get("device_hostname"), "sender_ip": unmapped.get("sender_ip"),
        "parser": meta.get("log_name"), "fields_verified": fields_verified(unmapped),
        "sequence_num": meta.get("sequence"), "event_uid": meta.get("uid"),
        "raw_id": _label(meta, "raw_id"), "raw_sha256": _label(meta, "raw_sha256"),
    }
    if include_ocsf:
        row["ocsf"] = json.dumps(e, default=str)
    return row


_KIND = {name: kind for name, kind, _ in COLUMNS}


def typed(row: Dict[str, Any]) -> Dict[str, Any]:
    """The row with each value in its column's type. A value that is not what its column holds (a
    port that is not a number) becomes null here; the event as the device gave it is still whole in
    the `ocsf` column, so nothing is lost, and one odd value cannot fail the whole file."""
    out = {}
    for name, value in row.items():
        kind = _KIND.get(name)
        if value is None or kind is None:
            out[name] = value
        elif kind in ("int64", "int32"):
            try:
                out[name] = int(value)
            except (TypeError, ValueError):
                out[name] = None
        elif kind == "bool":
            out[name] = bool(value)
        else:
            out[name] = value if isinstance(value, str) else str(value)
    return out


def arrow_schema():
    """The Parquet schema, so every file has the same column types (a batch in which no device
    reported bytes still has an int64 bytes column, not a column of type null)."""
    import pyarrow as pa
    types = {"int64": pa.int64(), "int32": pa.int32(), "string": pa.string(), "bool": pa.bool_()}
    return pa.schema([(name, types[kind]) for name, kind, _ in COLUMNS])
