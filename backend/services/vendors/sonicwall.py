"""SonicWall SonicOS syslog: id=firewall sn=... m=<message id> msg="..." src=IP:PORT:IFACE ..."""
import re
from typing import Optional

from .common import (
    AUTH_LOGON, AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_CLOSE, NA_OPEN,
    NA_REFUSE, NA_TRAFFIC, event, iso_from_formats, is_denied, parse_kv, to_int,
)
from .envelope import Envelope

NAME = "sonicwall_sonicos"
VENDOR, PRODUCT = "SonicWall", "SonicOS"
_EP = re.compile(r"^([0-9a-fA-F.:]+?):(\d+)(?::([^:]+))?")
_DETECTION_WORDS = ("ips ", "intrusion", "malware", "anti-virus", "gav", "botnet", "spyware", "attack", "scan",
                    "flood", "capture atp", "geo-ip")


def _endpoint(value: Optional[str]):
    """src/dst are IP:PORT:IFACE; the port may be empty ("172.16.2.2::X0") and IPv6 has its own colons."""
    if not value:
        return None, None, None
    import ipaddress
    parts = value.split(":")
    if len(parts) in (2, 3):
        try:
            ipaddress.ip_address(parts[0])
            return parts[0], to_int(parts[1]) if parts[1] else None, (parts[2] or None) if len(parts) == 3 else None
        except ValueError:
            pass
    m = _EP.match(value)
    if m:
        return m.group(1), to_int(m.group(2)), m.group(3)
    try:
        ipaddress.ip_address(value)
        return value, None, None
    except ValueError:
        return None, None, None  # not an address (e.g. an object name): kept in the vendor fields


def detect(env: Envelope) -> bool:
    msg = env.message
    return "id=firewall" in msg and " sn=" in f" {msg}" and " m=" in msg


def parse(env: Envelope) -> Optional[dict]:
    kv = parse_kv(env.message)
    if not kv:
        return None
    sip, sport, sif = _endpoint(kv.get("src"))
    dip, dport, dif = _endpoint(kv.get("dst"))
    msg = kv.get("msg") or ""
    low = msg.lower()
    proto = (kv.get("proto") or "").split("/")[0] or None
    common = dict(
        timestamp=iso_from_formats(kv.get("time"), ("%Y-%m-%d %H:%M:%S",)), original_time=kv.get("time"),
        device_hostname=kv.get("fw") or env.hostname, src_ip=sip, src_port=sport, dst_ip=dip, dst_port=dport,
        proto=proto, user=kv.get("usr") or kv.get("user"), severity={"0": "critical", "1": "critical", "2": "critical",
                                                                      "3": "high", "4": "medium", "5": "low"}.get(
            kv.get("pri", ""), "informational"),
        src_interface=sif, dst_interface=dif,
    )
    if "login" in low or "logged" in low or "authentication" in low:
        failed = any(w in low for w in ("denied", "fail", "bad credentials", "invalid", "locked"))
        return event(VENDOR, PRODUCT, AUTHENTICATION, AUTH_LOGON, "Logon", vendor_fields=kv,
                     action="failure" if failed else "success", auth_status="failure" if failed else "success",
                     **common)
    if any(w in low for w in _DETECTION_WORDS) or kv.get("ipscat") or kv.get("sid"):
        return event(VENDOR, PRODUCT, DETECTION_FINDING, vendor_fields=kv, signature=msg or kv.get("ipscat"),
                     rule_id=kv.get("sid") or kv.get("m"), action="deny" if is_denied(msg) else "alert", **common)
    if sip or dip:
        if is_denied(msg):
            activity, action = NA_REFUSE, "deny"
        elif "opened" in low:
            activity, action = NA_OPEN, "allow"
        elif "closed" in low:
            activity, action = NA_CLOSE, "allow"
        else:
            activity, action = NA_TRAFFIC, "allow"
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, activity, vendor_fields=kv, action=action,
                     bytes_out=to_int(kv.get("sent")), bytes_in=to_int(kv.get("rcvd")), **common)
    return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=kv, msg=msg, **common)
