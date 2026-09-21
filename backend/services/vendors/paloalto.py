"""
Palo Alto Networks PAN-OS default syslog format (comma-separated values).

Field positions follow the PAN-OS "Syslog Field Descriptions" for Traffic
and Threat logs (fields 1-46, 0-based below). Other log types (SYSTEM,
CONFIG, GLOBALPROTECT, ...) keep every column and are emitted as OCSF Base
Events until a dedicated mapping is added.
"""
import csv
import re
from typing import Optional

from .common import (
    BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_CLOSE, NA_OPEN, NA_REFUSE, NA_TRAFFIC,
    clean, event, iso_from_formats, is_denied, to_int,
)
from .envelope import Envelope

NAME = "paloalto_panos"
VENDOR, PRODUCT = "Palo Alto Networks", "PAN-OS"

_LOG_TYPES = {
    "TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "HIPMATCH", "GLOBALPROTECT", "USERID", "AUTHENTICATION",
    "DECRYPTION", "TUNNEL", "CORRELATION", "IPTAG", "AUDIT", "SCTP", "GTP",
}
_HEAD = re.compile(r"^[^,]*,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,]*,([A-Z]+),")
_TS_FORMATS = ("%Y/%m/%d %H:%M:%S",)

_COMMON = {
    1: "receive_time", 2: "serial_number", 3: "type", 4: "subtype", 6: "generated_time",
    7: "src", 8: "dst", 9: "natsrc", 10: "natdst", 11: "rule", 12: "srcuser", 13: "dstuser",
    14: "app", 15: "vsys", 16: "from_zone", 17: "to_zone", 18: "inbound_if", 19: "outbound_if",
    20: "log_action", 22: "session_id", 23: "repeat_count", 24: "sport", 25: "dport",
    26: "natsport", 27: "natdport", 28: "flags", 29: "proto", 30: "action",
}
_TRAFFIC = {
    31: "bytes", 32: "bytes_sent", 33: "bytes_received", 34: "packets", 35: "start_time",
    36: "elapsed_time", 37: "category", 39: "sequence_number", 40: "action_flags",
    41: "src_country", 42: "dst_country", 44: "packets_sent", 45: "packets_received",
    46: "session_end_reason",
}
_THREAT = {
    31: "url_or_filename", 32: "threat_id", 33: "category", 34: "severity", 35: "direction",
    36: "sequence_number", 37: "action_flags", 38: "src_location", 39: "dst_location",
    41: "content_type", 42: "pcap_id",
}
_THREAT_ID = re.compile(r"^(.*)\((\d+)\)\s*$")


def detect(env: Envelope) -> bool:
    m = _HEAD.match(env.message)
    return bool(m and m.group(1) in _LOG_TYPES)


def parse(env: Envelope) -> Optional[dict]:
    try:
        cols = next(csv.reader([env.message]))
    except (csv.Error, StopIteration):
        return None
    if len(cols) < 5:
        return None
    log_type = cols[3]
    layout = dict(_COMMON)
    if log_type == "TRAFFIC":
        layout.update(_TRAFFIC)
    elif log_type == "THREAT":
        layout.update(_THREAT)
    else:
        layout = {1: "receive_time", 2: "serial_number", 3: "type", 4: "subtype", 6: "generated_time"}

    f = {name: cols[i] for i, name in layout.items() if i < len(cols)}
    extras = {f"field_{i + 1}": v for i, v in enumerate(cols) if i not in layout and v}
    vendor_fields = {**f, **extras}

    ts = iso_from_formats(f.get("generated_time") or f.get("receive_time"), _TS_FORMATS)
    common = dict(
        timestamp=ts, original_time=f.get("generated_time"), device_hostname=env.hostname,
        device_serial=f.get("serial_number"),
    )

    if log_type == "TRAFFIC":
        action = f.get("action")
        subtype = (f.get("subtype") or "").lower()
        if is_denied(action) or subtype in ("deny", "drop"):
            activity = NA_REFUSE
        elif subtype == "start":
            activity = NA_OPEN
        elif subtype == "end":
            activity = NA_CLOSE
        else:
            activity = NA_TRAFFIC
        return event(
            VENDOR, PRODUCT, NETWORK_ACTIVITY, activity, vendor_fields=vendor_fields,
            src_ip=clean(f.get("src")), dst_ip=clean(f.get("dst")),
            src_port=to_int(f.get("sport")), dst_port=to_int(f.get("dport")),
            proto=clean(f.get("proto")), action=action, user=clean(f.get("srcuser")),
            bytes_out=to_int(f.get("bytes_sent")), bytes_in=to_int(f.get("bytes_received")),
            rule=clean(f.get("rule")), **common,
        )

    if log_type == "THREAT":
        threat = f.get("threat_id") or ""
        m = _THREAT_ID.match(threat)
        title, tid = (m.group(1).strip(), m.group(2)) if m else (threat, None)
        return event(
            VENDOR, PRODUCT, DETECTION_FINDING, vendor_fields=vendor_fields,
            src_ip=clean(f.get("src")), dst_ip=clean(f.get("dst")),
            src_port=to_int(f.get("sport")), dst_port=to_int(f.get("dport")),
            proto=clean(f.get("proto")), action=f.get("action"), user=clean(f.get("srcuser")),
            signature=title or f.get("subtype"), rule_id=tid, severity=f.get("severity"),
            threat_type=f.get("subtype"), **common,
        )

    return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=vendor_fields,
                 msg=f"PAN-OS {log_type} {f.get('subtype', '')}".strip(), **common)
