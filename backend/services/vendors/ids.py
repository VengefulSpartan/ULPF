"""
Network IDS/IPS sensors: Suricata EVE JSON, Zeek JSON logs and Snort alerts.

Snort writes an alert in whichever shape its output plugin was configured for, and a SOC does
not get to choose which one a sensor already uses, so the pack reads all five:

  fast          09/04-21:55:02 [**] [1:1000005:0] UDP Connection [**] [Priority: 1] {UDP} a:p -> b:q
  syslog        Sep  5 16:05:26 dev snort: [1:1000017:0] UDP Connection [Priority: 3] {UDP} a:p -> b:q
  full          a block of lines; the first names the rule and the message, the rest describe the
                packet. Line by line, the header is read as the finding and the packet lines are
                left to the generic parser rather than guessed at.
  alert_csv     09/04-21:45:37.536335 ,1,1000006,0,"TCP connection",TCP,src,sport,dst,dport,...
                (pfSense writes its own column set after the ports; both are read)
  alert_json    Snort 3's JSON: {"sid":..., "msg":..., "src_addr":..., "proto":"TCP", ...}
"""
import json
import re
from typing import Dict, List, Optional

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


# alert_csv's documented default column order, and the shorter set pfSense writes. Both start with
# the same ten fields, which is what the finding is built from; the rest is kept as vendor fields.
_CSV_COLUMNS = ("timestamp", "sig_generator", "sig_id", "sig_rev", "msg", "proto", "src", "srcport", "dst",
                "dstport", "ethsrc", "ethdst", "ethlen", "tcpflags", "tcpseq", "tcpack", "tcplen", "tcpwindow",
                "ttl", "tos", "id", "dgmlen", "iplen", "icmptype", "icmpcode", "icmpid", "icmpseq")
_CSV_COLUMNS_PFSENSE = ("timestamp", "sig_generator", "sig_id", "sig_rev", "msg", "proto", "src", "srcport",
                        "dst", "dstport", "id", "classification", "priority", "event_type", "action")
_CSV_TIME = ("%m/%d/%y-%H:%M:%S.%f", "%m/%d/%Y-%H:%M:%S.%f", "%m/%d-%H:%M:%S.%f", "%m/%d-%H:%M:%S")
_CSV_HEAD = re.compile(r"^\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*,\d+,\d+,\d+,")
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
# the first line of a full-format alert, with no packet detail on it: [**] [1:1000006:0] TCP connection [**]
_FULL_HEAD = re.compile(r"^\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.+?)\s*\[\*\*\]\s*$")
_JSON_KEYS = ('"pkt_num"', '"pkt_gen"', '"b64_data"', '"rule"')
_HUGE_FIELDS = ("b64_data",)   # the packet payload: megabytes per batch, and nothing reads it downstream


def _split_csv(line: str) -> List[str]:
    """Split on commas, keeping quoted messages (which contain commas) in one piece."""
    out, field, quoted = [], [], False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            out.append("".join(field).strip())
            field = []
        else:
            field.append(ch)
    out.append("".join(field).strip())
    return out


class Snort:
    NAME, VENDOR, PRODUCT = "snort_alert", "Cisco", "Snort"

    @staticmethod
    def detect(env: Envelope) -> bool:
        msg = env.message
        if _CSV_HEAD.match(msg.strip()):
            return True
        if _FULL_HEAD.match(msg.strip()):
            return True
        if msg.lstrip().startswith("{"):
            return '"msg"' in msg and '"sid"' in msg and any(k in msg for k in _JSON_KEYS)
        return bool(_SNORT.search(msg)) and ("snort" in (env.app or "").lower() or "[**]" in msg
                                             or "[Priority:" in msg or "[Classification:" in msg)

    @classmethod
    def parse(cls, env: Envelope) -> Optional[dict]:
        msg = env.message.strip()
        if _CSV_HEAD.match(msg):
            return cls._csv(env, msg)
        if msg.startswith("{"):
            return cls._json(env)
        head = _FULL_HEAD.match(msg)
        if head:
            return cls._full_header(env, head.groupdict())
        return cls._fast(env)

    @classmethod
    def _fast(cls, env: Envelope) -> Optional[dict]:
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
        return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING,
                     vendor_fields={**{k: v for k, v in g.items() if v}, "snort_format": "fast"},
                     signature=g["msg"].strip(), rule_id=f"{g['gid']}:{g['sid']}:{g['rev']}",
                     severity=_SNORT_PRIO.get(to_int(g.get("prio")), "medium"), threat_type=g.get("cls"),
                     src_ip=g["sip"], dst_ip=g["dip"], src_port=to_int(g.get("sport")), dst_port=to_int(g.get("dport")),
                     proto=g["proto"].lower(), action="alert", original_time=ts_raw, device_hostname=env.hostname)

    @classmethod
    def _full_header(cls, env: Envelope, g: Dict[str, str]) -> dict:
        """
        The first line of a full-format alert: the rule and its message, and nothing else.

        The addresses are on the next line of the block, which arrives as its own log line. Rather
        than hold state across lines and risk attaching one alert's addresses to another's, the
        finding is recorded without endpoints and the packet line is left to the generic parser,
        which reads "a:p -> b:q" on its own evidence.
        """
        return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING,
                     vendor_fields={**g, "snort_format": "full"}, signature=g["msg"].strip(),
                     rule_id=f"{g['gid']}:{g['sid']}:{g['rev']}", action="alert",
                     original_time=env.timestamp, device_hostname=env.hostname)

    @classmethod
    def _csv(cls, env: Envelope, line: str) -> Optional[dict]:
        parts = _split_csv(line)
        if len(parts) < 10:
            return None
        # both column sets share the first ten fields; after that pfSense writes its own, and the
        # give-away is field 10: a MAC address in Snort's own output, an IP id in pfSense's
        columns = _CSV_COLUMNS if (len(parts) > 10 and _MAC.match(parts[10])) else _CSV_COLUMNS_PFSENSE
        row = {k: v for k, v in zip(columns, parts) if v}
        for field in _HUGE_FIELDS:
            row.pop(field, None)
        priority = to_int(row.get("priority"))
        return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING,
                     vendor_fields={**row, "snort_format": "csv"},
                     signature=row.get("msg"), rule_id=f"{row.get('sig_generator')}:{row.get('sig_id')}:"
                                                        f"{row.get('sig_rev')}",
                     severity=_SNORT_PRIO.get(priority, "medium") if priority is not None else "medium",
                     threat_type=row.get("classification"), src_ip=row.get("src"), dst_ip=row.get("dst"),
                     src_port=to_int(row.get("srcport")), dst_port=to_int(row.get("dstport")),
                     proto=(row.get("proto") or "").lower() or None, action="alert",
                     timestamp=iso_from_formats(row.get("timestamp"), _CSV_TIME), original_time=row.get("timestamp"),
                     device_hostname=env.hostname)

    @classmethod
    def _json(cls, env: Envelope) -> Optional[dict]:
        e = _json(env)
        if not e or not e.get("msg"):
            return None
        fields = {k: v for k, v in e.items() if k not in _HUGE_FIELDS}
        priority = to_int(e.get("priority"))
        return event(cls.VENDOR, cls.PRODUCT, DETECTION_FINDING,
                     vendor_fields={**fields, "snort_format": "json"}, signature=e.get("msg"),
                     rule_id=e.get("rule") or f"{e.get('gid')}:{e.get('sid')}:{e.get('rev')}",
                     severity=_SNORT_PRIO.get(priority, "medium") if priority is not None else "medium",
                     threat_type=e.get("class") if e.get("class") not in (None, "none") else None,
                     src_ip=e.get("src_addr"), dst_ip=e.get("dst_addr"), src_port=to_int(e.get("src_port")),
                     dst_port=to_int(e.get("dst_port")), proto=(e.get("proto") or "").lower() or None,
                     action="alert", app_protocol=e.get("service") if e.get("service") != "unknown" else None,
                     timestamp=iso_from_epoch(e.get("seconds")), original_time=e.get("timestamp"),
                     device_hostname=env.hostname)
