"""
Network IDS/IPS sensors: Suricata EVE JSON, Zeek JSON logs and Snort alerts
(fast-alert and syslog forms).
"""
import json
import re
from typing import Optional

from .common import (
    BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY, NA_TRAFFIC, event, iso_from_epoch, iso_from_formats, to_int,
)
from .envelope import Envelope

_SURICATA_SEV = {1: "high", 2: "medium", 3: "low"}
_SNORT_PRIO = {1: "high", 2: "medium", 3: "low", 4: "informational"}
_SNORT = re.compile(
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s*(?:\[\*\*\]\s*)?"
    r"(?:\[Classification: (?P<cls>[^\]]+)\]\s*)?(?:\[Priority: (?P<prio>\d+)\]:?\s*)?"
    r"\{(?P<proto>[^}]+)\}\s+(?P<sip>[^\s]+?)(?::(?P<sport>\d+))?\s+->\s+(?P<dip>[^\s]+?)(?::(?P<dport>\d+))?\s*$")
_SNORT_TS = re.compile(r"^(?P<ts>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+")


def _json(env: Envelope) -> Optional[dict]:
    msg = env.message.strip()
    if not (msg.startswith("{") and msg.endswith("}")):
        return None
    try:
        obj = json.loads(msg)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


class Suricata:
    NAME, VENDOR, PRODUCT = "suricata_eve", "OISF", "Suricata"

    @staticmethod
    def detect(env: Envelope) -> bool:
        m = env.message
        return '"event_type"' in m and ('"flow_id"' in m or '"src_ip"' in m or '"in_iface"' in m)

    @classmethod
    def parse(cls, env: Envelope) -> Optional[dict]:
        e = _json(env)
        if not e:
            return None
        et = e.get("event_type")
        ts = e.get("timestamp")
        common = dict(timestamp=iso_from_formats(ts, ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")),
                      original_time=ts, src_ip=e.get("src_ip"), dst_ip=e.get("dest_ip"),
                      src_port=to_int(e.get("src_port")), dst_port=to_int(e.get("dest_port")),
                      proto=(e.get("proto") or "").lower() or None, device_hostname=e.get("host") or env.hostname,
                      event_type=et)
        if et == "alert":
            a = e.get("alert") or {}
            return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING, vendor_fields=e, signature=a.get("signature"),
                         rule_id=a.get("signature_id"),
                         severity=a["severity"] if isinstance(a.get("severity"), str)
                         else _SURICATA_SEV.get(a.get("severity"), "medium"),
                         action=a.get("action"), threat_type=a.get("category"), **common)
        if et in ("flow", "netflow", "dns", "http", "tls", "ssh", "fileinfo", "smb", "dhcp", "ftp", "smtp",
                  "anomaly", "quic", "rdp", "snmp", "krb5", "nfs", "tftp", "ike", "mqtt", "http2"):
            flow = e.get("flow") or {}
            return event(cls.VENDOR, cls.PRODUCT, NETWORK_ACTIVITY, NA_TRAFFIC, vendor_fields=e, action="allow",
                         bytes_out=to_int(flow.get("bytes_toserver")), bytes_in=to_int(flow.get("bytes_toclient")),
                         app_protocol=e.get("app_proto"), **common)
        return event(cls.VENDOR, cls.PRODUCT, BASE_EVENT, vendor_fields=e, msg=f"Suricata {et}", **common)


class Zeek:
    NAME, VENDOR, PRODUCT = "zeek_json", "Zeek", "Zeek"

    @staticmethod
    def detect(env: Envelope) -> bool:
        m = env.message
        return '"id.orig_h"' in m and '"ts"' in m

    @classmethod
    def parse(cls, env: Envelope) -> Optional[dict]:
        e = _json(env)
        if not e:
            return None
        common = dict(timestamp=iso_from_epoch(e.get("ts")), original_time=str(e.get("ts")),
                      src_ip=e.get("id.orig_h"), dst_ip=e.get("id.resp_h"), src_port=to_int(e.get("id.orig_p")),
                      dst_port=to_int(e.get("id.resp_p")), proto=e.get("proto"), device_hostname=env.hostname)
        if e.get("note"):  # notice.log
            return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING, vendor_fields=e, signature=e.get("note"),
                         rule_id=e.get("note"), severity="medium", msg=e.get("msg"), action="alert", **common)
        return event(cls.VENDOR, cls.PRODUCT, NETWORK_ACTIVITY, NA_TRAFFIC, vendor_fields=e, action="allow",
                     bytes_out=to_int(e.get("orig_bytes")), bytes_in=to_int(e.get("resp_bytes")),
                     app_protocol=e.get("service"), **common)


class Snort:
    NAME, VENDOR, PRODUCT = "snort_alert", "Cisco", "Snort"

    @staticmethod
    def detect(env: Envelope) -> bool:
        return bool(_SNORT.search(env.message)) and ("snort" in (env.app or "").lower() or "[**]" in env.message
                                                      or "[Priority:" in env.message or "[Classification:" in env.message)

    @classmethod
    def parse(cls, env: Envelope) -> Optional[dict]:
        msg = env.message
        ts_raw = env.timestamp
        m = _SNORT_TS.match(msg)
        if m:
            ts_raw = m.group("ts")
            msg = msg[m.end():]
        g = _SNORT.search(msg)
        if not g:
            return None
        g = g.groupdict()
        return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING, vendor_fields={k: v for k, v in g.items() if v},
                     signature=g["msg"].strip(), rule_id=f"{g['gid']}:{g['sid']}:{g['rev']}",
                     severity=_SNORT_PRIO.get(to_int(g.get("prio")), "medium"), threat_type=g.get("cls"),
                     src_ip=g["sip"], dst_ip=g["dip"], src_port=to_int(g.get("sport")), dst_port=to_int(g.get("dport")),
                     proto=g["proto"].lower(), action="alert", original_time=ts_raw, device_hostname=env.hostname)
