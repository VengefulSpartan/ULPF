"""
Check Point Log Exporter, "syslog" format: an RFC 5424 header followed by
[key:"value"; key:"value"; ...]. Check Point's own format is not valid RFC
5424 structured data, so it is parsed here rather than by the envelope.
(Log Exporter's CEF and LEEF formats are handled by the generic parsers.)
"""
import re
from typing import Optional

from .common import (
    AUTH_LOGON, AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_REFUSE, NA_TRAFFIC,
    event, iso_from_epoch, is_denied, proto_name, to_int,
)
from .envelope import Envelope

NAME = "checkpoint_log_exporter"
VENDOR = "Check Point"
_PAIR = re.compile(r'([A-Za-z_][\w\-.]*):+"((?:[^"\\]|\\.)*)"')
_THREAT_BLADES = ("ips", "threat emulation", "threat extraction", "anti-virus", "anti-bot", "anti-malware",
                  "smartdefense", "anti-exploit", "zero phishing", "url filtering", "application control",
                  "content awareness", "dlp", "threat prevention")


def detect(env: Envelope) -> bool:
    msg = env.message
    return msg.startswith("[") and ('origin:"' in msg or 'product:"' in msg or 'loguid:"' in msg) or \
        (env.app or "").lower() == "checkpoint"


def parse(env: Envelope) -> Optional[dict]:
    body = env.message
    start = body.find("[")
    if start >= 0:
        body = body[start:]
    kv = {k: v.replace('\\"', '"').replace("\\]", "]") for k, v in _PAIR.findall(body)}
    if not kv:
        return None
    product = kv.get("product") or "Security Gateway"
    blade = product.lower()
    action = kv.get("action") or kv.get("rule_action")
    common = dict(
        timestamp=iso_from_epoch(kv.get("time")) if kv.get("time") else None, original_time=kv.get("time") or env.timestamp,
        device_hostname=env.hostname, gateway_ip=kv.get("origin"),
        src_ip=kv.get("src"), dst_ip=kv.get("dst"), src_port=to_int(kv.get("s_port")),
        dst_port=to_int(kv.get("service")), proto=proto_name(kv.get("proto")),
        user=kv.get("src_user_name") or kv.get("user"),
        severity=kv.get("severity") or kv.get("confidence_level"),
    )

    if kv.get("auth_status") or (action or "").lower() in ("log in", "log out", "login", "logout"):
        ok = "fail" not in f"{kv.get('auth_status', '')} {kv.get('reason', '')}".lower()
        if (action or "").lower() in ("log out", "logout"):
            return event(VENDOR, product, AUTHENTICATION, 2, "Logoff", vendor_fields=kv, action="success",
                         auth_status="success", **common)
        return event(VENDOR, product, AUTHENTICATION, AUTH_LOGON, "Logon", vendor_fields=kv,
                     action="success" if ok else "failure", auth_status="success" if ok else "failure", **common)

    if any(b in blade for b in _THREAT_BLADES) or kv.get("protection_name") or kv.get("attack") or kv.get("malware_action"):
        title = kv.get("protection_name") or kv.get("attack") or kv.get("malware_action") or kv.get("appi_name") or product
        return event(VENDOR, product, DETECTION_FINDING, vendor_fields=kv, action=action, signature=title,
                     rule_id=kv.get("protection_id") or kv.get("loguid"), threat_type=product, **common)

    if kv.get("src") or kv.get("dst"):
        return event(VENDOR, product, NETWORK_ACTIVITY, NA_REFUSE if is_denied(action) else NA_TRAFFIC,
                     vendor_fields=kv, action=action, rule=kv.get("rule_name") or kv.get("rule_uid"), **common)

    return event(VENDOR, product, BASE_EVENT, vendor_fields=kv,
                 msg=kv.get("sys_message") or kv.get("message") or product, **common)
