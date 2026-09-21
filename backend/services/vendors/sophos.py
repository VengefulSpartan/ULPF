"""Sophos Firewall (SFOS / XG) syslog: key=value with device="SFW" or device_name=."""
from typing import Optional

from .common import (
    AUTH_LOGON, AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_REFUSE, NA_TRAFFIC,
    event, iso_from_formats, is_denied, parse_kv, proto_name, to_int,
)
from .envelope import Envelope

NAME = "sophos_firewall"
VENDOR, PRODUCT = "Sophos", "Sophos Firewall"
_DETECTION_TYPES = ("idp", "ips", "atp", "anti-virus", "anti-spam", "sandstorm", "zero-day protection",
                    "ssl/tls", "content filtering", "waf", "advanced threat")


def detect(env: Envelope) -> bool:
    msg = env.message
    return ('device="SFW"' in msg or "device=SFW" in msg) or ("log_type=" in msg and "log_component=" in msg)


def parse(env: Envelope) -> Optional[dict]:
    kv = parse_kv(env.message)
    if not kv:
        return None
    log_type = (kv.get("log_type") or "").lower()
    component = (kv.get("log_component") or "").lower()
    subtype = kv.get("log_subtype") or kv.get("status") or ""
    ts = kv.get("timestamp")
    iso = iso_from_formats(ts, ("%Y-%m-%dT%H:%M:%S%z",)) if ts else iso_from_formats(
        f"{kv.get('date', '')} {kv.get('time', '')}".strip(), ("%Y-%m-%d %H:%M:%S",))
    common = dict(
        timestamp=iso, original_time=ts or f"{kv.get('date', '')} {kv.get('time', '')}".strip() or None,
        device_hostname=kv.get("device_name"), src_ip=kv.get("src_ip"), dst_ip=kv.get("dst_ip"),
        src_port=to_int(kv.get("src_port")), dst_port=to_int(kv.get("dst_port")),
        proto=proto_name(kv.get("protocol")), user=kv.get("user_name") or kv.get("user") or None,
        severity=kv.get("severity") or kv.get("priority"),
    )
    if log_type == "firewall":
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_REFUSE if is_denied(subtype) else NA_TRAFFIC,
                     vendor_fields=kv, action=subtype, rule=kv.get("fw_rule_id"),
                     bytes_out=to_int(kv.get("sent_bytes") or kv.get("bytes_sent")),
                     bytes_in=to_int(kv.get("recv_bytes") or kv.get("bytes_received")), **common)
    if any(t in log_type for t in _DETECTION_TYPES):
        title = kv.get("signature_msg") or kv.get("virus") or kv.get("threatname") or kv.get("reason") or \
            f"{kv.get('log_type')} {kv.get('log_component', '')}".strip()
        return event(VENDOR, PRODUCT, DETECTION_FINDING, vendor_fields=kv, action=subtype, signature=title,
                     rule_id=kv.get("signature_id") or kv.get("log_id"), threat_type=kv.get("log_type"), **common)
    if "authentication" in component or "vpn" in component or "login" in subtype.lower() or \
            (log_type == "event" and "auth" in (kv.get("message") or "").lower()):
        failed = any(w in f"{subtype} {kv.get('status', '')} {kv.get('message', '')}".lower()
                     for w in ("fail", "denied", "invalid"))
        return event(VENDOR, PRODUCT, AUTHENTICATION, AUTH_LOGON, "Logon", vendor_fields=kv,
                     action="failure" if failed else "success", auth_status="failure" if failed else "success", **common)
    return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=kv, msg=kv.get("message") or kv.get("log_type"), **common)
