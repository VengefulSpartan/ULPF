"""
Wire formats for outputs: RFC 5424 syslog, ArcSight CEF, IBM LEEF 2.0,
Graylog GELF 1.1 and OpenTelemetry OTLP/JSON log records.
All take a strict OCSF event (see backend.services.normalization.ocsf_export).
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

PRODUCT_VENDOR, PRODUCT_NAME, PRODUCT_VERSION = "TRACELOG", "TRACELOG", "1.0"

# OCSF severity_id -> syslog severity (RFC 5424) / CEF 0-10 / OTel severityNumber
SYSLOG_SEV = {0: 6, 1: 6, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 99: 6}
CEF_SEV = {0: 0, 1: 1, 2: 3, 3: 5, 4: 8, 5: 10, 6: 10, 99: 0}
OTEL_SEV = {0: (0, "UNSPECIFIED"), 1: (9, "INFO"), 2: (10, "INFO2"), 3: (13, "WARN"), 4: (17, "ERROR"),
            5: (21, "FATAL"), 6: (21, "FATAL"), 99: (9, "INFO")}


def ts_iso(ocsf: Dict[str, Any]) -> str:
    ms = ocsf.get("time") or 0
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hostname_of(ocsf: Dict[str, Any], default: str = "tracelog") -> str:
    u = ocsf.get("unmapped") or {}
    return str(u.get("device_hostname") or u.get("sender_ip") or default).replace(" ", "_")[:255]


def summary(ocsf: Dict[str, Any]) -> str:
    src = (ocsf.get("src_endpoint") or {}).get("ip")
    dst = (ocsf.get("dst_endpoint") or {}).get("ip")
    parts = [ocsf.get("type_name") or ""]
    if (ocsf.get("finding_info") or {}).get("title"):
        parts.append(ocsf["finding_info"]["title"])
    if src or dst:
        parts.append(f"{src or '?'} -> {dst or '?'}")
    if ocsf.get("action"):
        parts.append(ocsf["action"])
    return " | ".join(p for p in parts if p)


def flatten(obj: Any, prefix: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{sep}{k}" if prefix else str(k), sep))
    elif isinstance(obj, list):
        out[prefix] = json.dumps(obj, default=str)
    else:
        out[prefix] = obj
    return out


KEY_FIELDS = ("class_uid", "class_name", "activity_name", "type_uid", "severity_id", "severity", "action", "disposition",
              "status", "src_endpoint.ip", "src_endpoint.port", "dst_endpoint.ip", "dst_endpoint.port",
              "connection_info.protocol_name", "user.name", "finding_info.title", "finding_info.uid",
              "metadata.uid", "metadata.product.vendor_name", "metadata.product.name", "metadata.log_name")


def key_attributes(ocsf: Dict[str, Any]) -> Dict[str, Any]:
    flat = flatten({k: v for k, v in ocsf.items() if k not in ("raw_data", "unmapped", "observables")})
    return {k: flat[k] for k in KEY_FIELDS if flat.get(k) not in (None, "")}


# ---------------------------------------------------------------- RFC 5424 syslog
def rfc5424(message: str, ocsf: Dict[str, Any], app_name: str = "tracelog", facility: int = 20) -> str:
    pri = facility * 8 + SYSLOG_SEV.get(ocsf.get("severity_id") or 0, 6)
    msgid = f"OCSF{ocsf.get('class_uid', 0)}"
    return f"<{pri}>1 {ts_iso(ocsf)} {hostname_of(ocsf)} {app_name} - {msgid} - {message}"


# ---------------------------------------------------------------- CEF
def _cef_header(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def cef(ocsf: Dict[str, Any]) -> str:
    src, dst = ocsf.get("src_endpoint") or {}, ocsf.get("dst_endpoint") or {}
    meta = ocsf.get("metadata") or {}
    labels = {l.split("=", 1)[0]: l.split("=", 1)[1] for l in meta.get("labels") or [] if "=" in l}
    ext: List[Tuple[str, Any]] = [
        ("rt", ocsf.get("time")), ("src", src.get("ip")), ("spt", src.get("port")), ("dst", dst.get("ip")),
        ("dpt", dst.get("port")), ("proto", (ocsf.get("connection_info") or {}).get("protocol_name")),
        ("act", ocsf.get("action") or ocsf.get("disposition")), ("suser", (ocsf.get("user") or {}).get("name")),
        ("outcome", ocsf.get("status")), ("in", (ocsf.get("traffic") or {}).get("bytes_in")),
        ("out", (ocsf.get("traffic") or {}).get("bytes_out")), ("dvchost", hostname_of(ocsf, "")),
        ("externalId", meta.get("uid")), ("cat", ocsf.get("category_name")),
        ("cs1Label", "ocsfClass"), ("cs1", ocsf.get("class_name")),
        ("cs2Label", "sourceVendor"), ("cs2", (meta.get("product") or {}).get("vendor_name")),
        ("cs3Label", "rawSha256"), ("cs3", labels.get("tracelog.raw_sha256")),
        ("cs4Label", "parser"), ("cs4", meta.get("log_name")),
        ("msg", ocsf.get("message")),
    ]
    name = (ocsf.get("finding_info") or {}).get("title") or ocsf.get("type_name") or "event"
    header = "|".join(_cef_header(x) for x in (
        "CEF:0", PRODUCT_VENDOR, PRODUCT_NAME, PRODUCT_VERSION, ocsf.get("type_uid", 0), name,
        CEF_SEV.get(ocsf.get("severity_id") or 0, 0)))
    return header + "|" + " ".join(f"{k}={_cef_value(v)}" for k, v in ext if v not in (None, ""))


# ---------------------------------------------------------------- LEEF 2.0 (tab-delimited)
def leef(ocsf: Dict[str, Any]) -> str:
    src, dst = ocsf.get("src_endpoint") or {}, ocsf.get("dst_endpoint") or {}
    meta = ocsf.get("metadata") or {}
    dt = datetime.fromtimestamp((ocsf.get("time") or 0) / 1000.0, tz=timezone.utc)
    attrs: List[Tuple[str, Any]] = [
        ("devTime", dt.strftime("%b %d %Y %H:%M:%S")), ("devTimeFormat", "MMM dd yyyy HH:mm:ss"),
        ("cat", ocsf.get("class_name")), ("sev", CEF_SEV.get(ocsf.get("severity_id") or 0, 0)),
        ("src", src.get("ip")), ("srcPort", src.get("port")), ("dst", dst.get("ip")), ("dstPort", dst.get("port")),
        ("proto", (ocsf.get("connection_info") or {}).get("protocol_name")),
        ("usrName", (ocsf.get("user") or {}).get("name")), ("action", ocsf.get("action") or ocsf.get("disposition")),
        ("outcome", ocsf.get("status")), ("identHostName", hostname_of(ocsf, "")),
        ("ocsfClassUid", ocsf.get("class_uid")), ("ocsfTypeUid", ocsf.get("type_uid")),
        ("findingTitle", (ocsf.get("finding_info") or {}).get("title")), ("eventId", meta.get("uid")),
        ("sourceVendor", (meta.get("product") or {}).get("vendor_name")), ("msg", ocsf.get("message")),
    ]
    body = "\t".join(f"{k}={str(v).replace(chr(9), ' ')}" for k, v in attrs if v not in (None, ""))
    return f"LEEF:2.0|{PRODUCT_VENDOR}|{PRODUCT_NAME}|{PRODUCT_VERSION}|{ocsf.get('type_uid', 0)}|x09|{body}"


# ---------------------------------------------------------------- GELF 1.1
def gelf(ocsf: Dict[str, Any]) -> Dict[str, Any]:
    msg: Dict[str, Any] = {
        "version": "1.1", "host": hostname_of(ocsf), "short_message": summary(ocsf) or "event",
        "timestamp": (ocsf.get("time") or 0) / 1000.0, "level": SYSLOG_SEV.get(ocsf.get("severity_id") or 0, 6),
    }
    if ocsf.get("raw_data"):
        msg["full_message"] = ocsf["raw_data"]
    for k, v in flatten({k: v for k, v in ocsf.items() if k != "raw_data"}, sep="_").items():
        key = "_" + "".join(c if c.isalnum() or c in "_.-" else "_" for c in k)
        if key != "_id" and v not in (None, ""):
            msg[key] = v
    return msg


# ---------------------------------------------------------------- OTLP/JSON
def _otel_value(v: Any) -> Dict[str, Any]:
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def otlp_logs(events: Iterable[Dict[str, Any]], service_name: str = "tracelog",
              resource_attrs: Dict[str, Any] = None) -> Dict[str, Any]:
    records = []
    for e in events:
        sev_num, sev_text = OTEL_SEV.get(e.get("severity_id") or 0, (9, "INFO"))
        ns = str(int(e.get("time") or 0) * 1_000_000)
        attrs = {f"ocsf.{k}": v for k, v in key_attributes(e).items()}
        attrs["log.source"] = hostname_of(e)
        records.append({
            "timeUnixNano": ns, "observedTimeUnixNano": ns, "severityNumber": sev_num, "severityText": sev_text,
            "body": {"stringValue": json.dumps(e, default=str, separators=(",", ":"))},
            "attributes": [{"key": k, "value": _otel_value(v)} for k, v in attrs.items()],
        })
    res = {"service.name": service_name, "telemetry.sdk.name": "tracelog", **(resource_attrs or {})}
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": k, "value": _otel_value(v)} for k, v in res.items()]},
        "scopeLogs": [{"scope": {"name": "tracelog.ocsf", "version": "1.1.0"}, "logRecords": records}],
    }]}
