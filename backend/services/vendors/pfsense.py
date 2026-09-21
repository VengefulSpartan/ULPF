"""
pfSense / OPNsense packet filter log (filterlog): comma-separated fields per
Netgate's "Raw Filter Log Format". Common fields, then IPv4 or IPv6 fields,
then protocol-specific fields.
"""
from typing import Optional

from .common import NETWORK_ACTIVITY, NA_REFUSE, NA_TRAFFIC, event, iso_from_formats, to_int
from .envelope import Envelope

NAME = "pfsense_filterlog"
VENDOR, PRODUCT = "Netgate", "pfSense/OPNsense filterlog"
_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z")


def detect(env: Envelope) -> bool:
    return (env.app or "") == "filterlog" or env.message.startswith("filterlog")


def parse(env: Envelope) -> Optional[dict]:
    msg = env.message
    if msg.startswith("filterlog"):
        msg = msg.split(":", 1)[-1].strip()
    f = msg.split(",")
    if len(f) < 9:
        return None
    vf = {"rule_number": f[0], "sub_rule": f[1], "anchor": f[2], "tracker": f[3], "interface": f[4],
          "reason": f[5], "action": f[6], "direction": f[7], "ip_version": f[8]}
    if f[8] == "4" and len(f) >= 20:
        vf.update(tos=f[9], ecn=f[10], ttl=f[11], id=f[12], offset=f[13], flags=f[14], protocol_id=f[15],
                  protocol=f[16].lower(), length=f[17], src=f[18], dst=f[19])
        tail = f[20:]
    elif f[8] == "6" and len(f) >= 17:
        vf.update(class_=f[9], flow_label=f[10], hop_limit=f[11], protocol=f[12].lower(), protocol_id=f[13],
                  length=f[14], src=f[15], dst=f[16])
        tail = f[17:]
    else:
        return None
    if vf["protocol"] in ("tcp", "udp") and len(tail) >= 2:
        vf.update(src_port=tail[0], dst_port=tail[1], data_length=tail[2] if len(tail) > 2 else None)
        if vf["protocol"] == "tcp" and len(tail) > 3:
            vf["tcp_flags"] = tail[3]
    action = vf["action"]
    return event(VENDOR, PRODUCT, NETWORK_ACTIVITY, NA_REFUSE if action in ("block", "reject") else NA_TRAFFIC,
                 vendor_fields=vf, action=action, src_ip=vf["src"], dst_ip=vf["dst"],
                 src_port=to_int(vf.get("src_port")), dst_port=to_int(vf.get("dst_port")), proto=vf["protocol"],
                 rule=vf["rule_number"], timestamp=iso_from_formats(env.timestamp, _TS_FORMATS),
                 original_time=env.timestamp, device_hostname=env.hostname)
