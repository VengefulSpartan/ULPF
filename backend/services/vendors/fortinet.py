"""
Fortinet FortiGate (FortiOS) default syslog format: key=value pairs with
header fields date, time, devname, devid, logid, type, subtype, level.
"""
from typing import Optional

from .common import (
    AUTH_LOGOFF, AUTH_LOGON, AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY,
    NA_CLOSE, NA_REFUSE, NA_TRAFFIC, event, iso_from_epoch, iso_from_formats, is_denied,
    parse_kv, proto_name, to_int,
)
from .envelope import Envelope

NAME = "fortinet_fortigate"
VENDOR, PRODUCT = "Fortinet", "FortiGate"

_UTM_DETECTIONS = {"ips", "virus", "anomaly", "botnet", "dlp", "waf", "emailfilter", "webfilter", "app-ctrl",
                   "icap", "file-filter", "ssl", "dns", "voip", "cifs", "ztna", "virtual-patch"}
_CLOSE_ACTIONS = {"close", "timeout", "client-rst", "server-rst", "ip-conn"}


def detect(env: Envelope) -> bool:
    msg = env.message
    if "logid=" in msg and "type=" in msg and ("devid=" in msg or "devname=" in msg or "eventtime=" in msg
                                                 or msg.startswith("date=")):
        return True
    return msg.startswith("date=") and "devname=" in msg


def parse(env: Envelope) -> Optional[dict]:
    kv = parse_kv(env.message)
    if not kv:
        return None
    log_type, subtype = kv.get("type", ""), kv.get("subtype", "")
    action = kv.get("action") or kv.get("utmaction")
    ts = iso_from_epoch(kv.get("eventtime")) if kv.get("eventtime") else None
    if not ts:
        ts = iso_from_formats(f"{kv.get('date', '')} {kv.get('time', '')}".strip(),
                              ("%Y-%m-%d %H:%M:%S",), tz_offset=kv.get("tz"))
    common = dict(
        timestamp=ts, original_time=f"{kv.get('date', '')} {kv.get('time', '')}".strip() or None,
        device_hostname=kv.get("devname"), src_ip=kv.get("srcip"), dst_ip=kv.get("dstip"),
        src_port=to_int(kv.get("srcport")), dst_port=to_int(kv.get("dstport")),
        proto=proto_name(kv.get("proto")), user=kv.get("user") or kv.get("unauthuser"),
        severity=kv.get("crlevel") or kv.get("severity") or kv.get("level"),
    )

    if log_type == "traffic":
        if is_denied(action):
            activity = NA_REFUSE
        elif action in _CLOSE_ACTIONS:
            activity = NA_CLOSE
        else:
            activity = NA_TRAFFIC
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, activity, vendor_fields=kv, action=action,
                     bytes_out=to_int(kv.get("sentbyte")), bytes_in=to_int(kv.get("rcvdbyte")),
                     rule=kv.get("policyid"), **common)

    if log_type == "utm" and subtype in _UTM_DETECTIONS:
        if kv.get("attack") or kv.get("virus"):
            title = kv.get("attack") or kv.get("virus")
        elif subtype == "webfilter" and kv.get("hostname"):
            title = f"{kv.get('catdesc') or 'Web filter'}: {kv.get('hostname')}"
        else:
            title = kv.get("app") or kv.get("msg") or subtype
        return event(VENDOR, PRODUCT, DETECTION_FINDING, vendor_fields=kv, action=action,
                     signature=title, rule_id=kv.get("attackid") or kv.get("virusid") or kv.get("logid"),
                     threat_type=subtype, **common)

    desc = f"{kv.get('logdesc', '')} {kv.get('msg', '')} {action or ''}".lower()
    auth_scope = (log_type == "event" and subtype in ("vpn", "user", "system")) or log_type in ("vpn", "user")
    if auth_scope and any(
            w in desc for w in ("login", "logon", "logout", "auth", "tunnel-up", "tunnel-down")):
        logoff = any(w in desc for w in ("logout", "logoff", "tunnel-down"))
        # status= is the device's own verdict on admin and VPN logins; the words in the description
        # are the fallback for the events that carry none
        status = str(kv.get("status") or "").lower()
        if status in ("success", "succeeded"):
            failed = False
        elif status in ("failure", "failed", "fail", "denied"):
            failed = True
        else:
            failed = any(w in desc for w in ("fail", "denied", "invalid", "reject"))
        return event(VENDOR, PRODUCT, AUTHENTICATION, AUTH_LOGOFF if logoff else AUTH_LOGON,
                     "Logoff" if logoff else "Logon", vendor_fields=kv,
                     action="failure" if failed else "success",
                     auth_status="failure" if failed else "success",
                     **{**common, "src_ip": common["src_ip"] or kv.get("remip")})

    return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=kv, msg=kv.get("logdesc") or kv.get("msg"), **common)
