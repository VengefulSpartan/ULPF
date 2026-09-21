"""
Juniper SRX security logs: RT_FLOW (session create/close/deny), RT_IDP and
RT_SCREEN, in both "structured-data" (RFC 5424 [junos@2636... k="v"]) and
plain text modes.
"""
import re
from typing import Optional

from .common import (
    BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_CLOSE, NA_OPEN, NA_REFUSE,
    NA_TRAFFIC, clean, event, iso_from_formats, parse_kv, proto_name, to_int,
)
from .envelope import Envelope

NAME = "juniper_srx"
VENDOR, PRODUCT = "Juniper Networks", "SRX"
_TAGS = ("RT_FLOW", "RT_IDP", "RT_SCREEN", "RT_UTM", "RT_AAMW", "RT_SECINTEL")
_PLAIN = re.compile(
    r"(?P<tag>RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY))(?:_LS)?:\s+session (?P<verb>created|closed|denied)(?: (?P<reason>[^:]+):)?\s+"
    r"(?P<sip>[^\s/]+)/(?P<sport>\d+)->(?P<dip>[^\s/]+)/(?P<dport>\d+)\s+(?:0x\w+\s+)?(?P<service>\S+)\s+(?P<rest>.*)$")
_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
               "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")


def detect(env: Envelope) -> bool:
    if any(k.startswith("junos@") for k in env.sd):
        return True
    head = (env.msgid or "") + " " + env.message[:40]
    return any(t in head for t in _TAGS)


_TAG_IN_MSG = re.compile(r"\b((?:RT|APPTRACK)_[A-Z_]+)\b")
_BRACKET = re.compile(r"\[(?:junos@\S+\s+)?([^\]]*=\"[^\]]*)\]")


def parse(env: Envelope) -> Optional[dict]:
    params = next((v for k, v in env.sd.items() if k.startswith("junos@")), None)
    tag = env.msgid or ""
    if not tag.startswith(("RT_", "APPTRACK_")):
        m = _TAG_IN_MSG.search(env.message)
        tag = m.group(1) if m else tag
    if params is None:  # structured data without a valid SD-ID, or relayed through an RFC 3164 collector
        b = _BRACKET.search(env.message)
        if b:
            params = parse_kv(b.group(1))
    common = dict(timestamp=iso_from_formats(env.timestamp, _TS_FORMATS), original_time=env.timestamp,
                  device_hostname=env.hostname, message_type=tag)

    if params is None:  # plain text mode
        m = _PLAIN.search(env.message)
        if not m:
            return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields={"text": env.message}, msg=env.message, **common)
        g = m.groupdict()
        tag = g["tag"]
        rest = g["rest"].split()
        proto = next((proto_name(t.split("(")[0]) for t in rest if re.match(r"^\d+(\(\d+\))?$", t)), None)
        params = {"source-address": g["sip"], "source-port": g["sport"], "destination-address": g["dip"],
                  "destination-port": g["dport"], "service-name": g["service"], "reason": g.get("reason"),
                  "text": env.message}
        common["message_type"] = tag
    else:
        proto = proto_name(params.get("protocol-id"))

    net = dict(src_ip=clean(params.get("source-address")), dst_ip=clean(params.get("destination-address")),
               src_port=to_int(params.get("source-port")), dst_port=to_int(params.get("destination-port")),
               proto=proto, user=clean(params.get("username")), rule=clean(params.get("policy-name")))

    if tag.startswith(("RT_FLOW_SESSION_CREATE", "APPTRACK_SESSION_CREATE")):
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_OPEN, vendor_fields=params, action="allow", **net, **common)
    if tag.startswith(("RT_FLOW_SESSION_CLOSE", "APPTRACK_SESSION_CLOSE")):
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_CLOSE, vendor_fields=params, action="allow",
                     bytes_out=to_int(params.get("bytes-from-client")), bytes_in=to_int(params.get("bytes-from-server")),
                     close_reason=params.get("reason"), **net, **common)
    if tag.startswith("APPTRACK_SESSION"):  # volume and route updates for an open session
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_TRAFFIC, vendor_fields=params, action="allow",
                     bytes_out=to_int(params.get("bytes-from-client")), bytes_in=to_int(params.get("bytes-from-server")),
                     **net, **common)
    if tag.startswith("RT_FLOW_SESSION_DENY"):
        return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_REFUSE, vendor_fields=params, action="deny", **net, **common)
    if tag.startswith(("RT_IDP", "RT_SCREEN", "RT_AAMW", "RT_SECINTEL", "RT_UTM")):
        title = params.get("attack-name") or params.get("threat-name") or params.get("category") or tag
        return event(VENDOR, PRODUCT, DETECTION_FINDING, vendor_fields=params, action=params.get("action"),
                     signature=title, rule_id=params.get("rule-name") or tag, severity=params.get("threat-severity")
                     or params.get("severity"), threat_type=tag, **net, **common)
    return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=params, msg=env.message or tag, **common)
