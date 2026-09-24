"""
Cisco ASA and Firepower Threat Defense (FTD) syslog messages: %ASA-<level>-<id>
or %FTD-<level>-<id>. Message layouts follow Cisco's "ASA Series Syslog
Messages" reference. Unrecognised message ids are kept as Base Events with
their text, so nothing is dropped.

Connection direction. A Built message says who opened the connection
("Built outbound ... for outside:A to inside:B" means B, inside, opened it to A).
The Teardown message for the same connection lists the two ends in the same
order but does not say which one opened it, so reading its first address as the
source turns every outbound DNS lookup into "from port 53". The pack therefore
remembers the direction of recent Built messages, keyed by device and connection
id, and a Teardown takes its direction from its own connection's Built message.
When that message was not seen (it arrived before a restart, or went to another
worker) the Teardown keeps both ends in vendor_fields and leaves source and
destination empty: a missing field beats a wrong field.
"""
import ipaddress
import re
import threading
from collections import OrderedDict
from typing import Hashable, Optional, Tuple

from .common import (
    AUTH_LOGOFF, AUTH_LOGON, AUTHENTICATION, BASE_EVENT, DETECTION_FINDING, NETWORK_ACTIVITY,
    NA_CLOSE, NA_OPEN, NA_REFUSE, NA_TRAFFIC, event, iso_from_formats, to_int,
)
from .envelope import SYSLOG_SEVERITY_TEXT, Envelope

NAME = "cisco_asa"
_TAG = re.compile(r"%(ASA|FTD|FWSM|PIX)-(?:[A-Za-z_]+-)?(\d)-(\d{6}):\s?(.*)$", re.S)
_TS_FORMATS = ("%b %d %Y %H:%M:%S", "%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z")

_EP = r"(?P<{p}if>[^:\s]+):(?P<{p}ip>[^\s/]+)/(?P<{p}port>\d+)"


def _ep(p: str) -> str:
    return _EP.format(p=p)


RULES = {
    "built": re.compile(
        r"Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP|SCTP) connection (?P<cid>\d+) for " + _ep("f") +
        r"(?: \([^)]*\))?(?:\((?P<fuser>[^)]*)\))? to " + _ep("t") + r"(?: \([^)]*\))?(?:\((?P<tuser>[^)]*)\))?"),
    "teardown": re.compile(
        r"Teardown (?P<proto>TCP|UDP|SCTP) connection (?P<cid>\d+) for " + _ep("f") +
        r"(?:\((?P<fuser>[^)]*)\)| (?!to )(?P<fuser2>\S+))? to " + _ep("t") +
        r"(?:\((?P<tuser>[^)]*)\)| (?!duration )(?P<tuser2>\S+))?(?: duration (?P<duration>\S+))?"
        r"(?: bytes (?P<bytes>\d+))?(?: (?P<reason>.+))?"),
    "gre": re.compile(
        r"(?P<verb>Built|Teardown) GRE connection (?P<cid>\d+) from (?P<sif>[^:\s]+):(?P<sip>[^\s/]+)(?:/(?P<sport>\d+))? "
        r"to (?P<dif>[^:\s]+):(?P<dip>[^\s/]+)(?:/(?P<dport>\d+))?(?: duration (?P<duration>\S+))?(?: bytes (?P<bytes>\d+))?"),
    "nat": re.compile(
        r"(?P<verb>Built|Teardown) (?:dynamic|static) (?P<proto>TCP|UDP|ICMP) translation from (?P<sif>[^:\s]+):"
        r"(?P<sip>[^\s/]+)/(?P<sport>\d+)\S* to (?P<mif>[^:\s]+):(?P<mip>[^\s/]+)/(?P<mport>\d+)"),
    "spoof": re.compile(r"Deny IP spoof from \((?P<sip>[^)]+)\) to (?P<dip>\S+) on interface (?P<dif>\S+)"),
    "url": re.compile(r"(?P<sip>\S+) Accessed URL (?P<dip>[^:\s]+):(?P<url>\S+)"),
    "logout": re.compile(r"User logged out: Uname: (?P<user>.+)$"),
    "icmp": re.compile(
        r"(?P<verb>Built|Teardown) (?:(?P<dir>inbound|outbound) )?ICMP connection (?:(?P<cid>\d+) )?for faddr "
        r"(?P<fip>[^\s/]+)/(?P<fid>\d+)(?:\([^)]*\))? gaddr (?P<gip>[^\s/]+)/\d+ laddr (?P<lip>[^\s/]+)/(?P<lid>\d+)"),
    "deny_acl": re.compile(
        r"Deny (?P<proto>\S+) src (?P<sif>[^:\s]+):(?P<sip>[^\s/(]+)(?:/(?P<sport>\d+))?(?:\([^)]*\))? dst "
        r"(?P<dif>[^:\s]+):(?P<dip>[^\s/(]+)(?:/(?P<dport>\d+))?(?:\([^)]*\))?(?: \(?type \d+, code \d+\)?,?)? "
        r"by access-group \"(?P<acl>[^\"]+)\""),
    "deny_inbound_tcp": re.compile(
        r"Inbound (?P<proto>TCP) connection denied from (?P<sip>[^\s/]+)/(?P<sport>\d+) to "
        r"(?P<dip>[^\s/]+)/(?P<dport>\d+) flags (?P<flags>.*?) on interface (?P<dif>\S+)"),
    "deny_udp": re.compile(
        r"Deny (?P<dir>inbound|outbound) (?P<proto>UDP) from (?P<sip>[^\s/]+)/(?P<sport>\d+) to "
        r"(?P<dip>[^\s/]+)/(?P<dport>\d+)"),
    "deny_noconn": re.compile(
        r"Deny (?P<proto>TCP) \(no connection\) from (?P<sip>[^\s/]+)/(?P<sport>\d+) to "
        r"(?P<dip>[^\s/]+)/(?P<dport>\d+) flags (?P<flags>.*?) on interface (?P<dif>\S+)"),
    "acl_hit": re.compile(
        r"access-list (?P<acl>\S+) (?P<verdict>permitted|denied|est-allowed) (?P<proto>\S+) "
        r"(?P<sif>[^/\s]+)/(?P<sip>[^\s(]+)\((?P<sport>\d+)\)(?:\([^)]*\))? -> "
        r"(?P<dif>[^/\s]+)/(?P<dip>[^\s(]+)\((?P<dport>\d+)\)"),
    "acl_to_box": re.compile(
        r"(?P<proto>TCP|UDP|ICMP) access denied by ACL from (?P<sip>[^\s/]+)/(?P<sport>\d+) to "
        + _ep("d")),
    "ips": re.compile(r"IPS:(?P<sid>\d+) (?P<name>.+?) from (?P<sip>\S+) to (?P<dip>\S+) on interface (?P<dif>\S+)"),
    "threat_rate": re.compile(r"\[\s*(?P<obj>[^\]]+?)\s*\] drop (?P<rate>\S+) exceeded"),
    "aaa_ok": re.compile(r"AAA user authentication Successful : server = (?P<server>\S+) : user = (?P<user>.+)$"),
    "aaa_rejected": re.compile(
        r"AAA user authentication Rejected : reason = (?P<reason>.+?) : (?:server = (?P<server>\S+)|local database)"
        r" : user = (?P<user>.+?)(?: : user IP = (?P<ip>\S+))?$"),
    "anyconnect": re.compile(
        r"Group <(?P<group>[^>]*)> User <(?P<user>[^>]*)> IP <(?P<ip>[^>]*)> "
        r"(?:AnyConnect parent session (?P<ac>started|terminated)|WebVPN session (?P<wv>started|terminated)|"
        r"IPv4 Address <[^>]*> assigned to session)"),
    "user_auth": re.compile(r"User authentication (?P<res>succeeded|failed): (?:IP address: (?P<ip>[^,]+), )?Uname: (?P<user>.+)$"),
    "mgmt_login": re.compile(
        r"Login (?P<res>denied|permitted) from (?P<sip>[^\s/]+)/(?P<sport>\d+) to (?P<dif>[^:\s]+):(?P<dip>[^\s/]+)/"
        r"(?P<dport>\S+) for user \"?(?P<user>[^\"]+?)\"?$"),
}


class _OpenConnections:
    """Direction of recently built connections, so their Teardown can be read the same way.

    Keyed by device and connection id, and each entry also keeps the connection's two ends: a
    Teardown takes the direction only if its ends match, so two devices that send no hostname
    and happen to reuse a connection id cannot lend each other a direction. Bounded: the oldest
    entry is forgotten first, and an entry is dropped when its Teardown arrives, so memory stays
    flat on a busy firewall. Locked because receivers parse on several threads.
    """

    def __init__(self, limit: int = 65536):
        self.limit = limit
        self._items: "OrderedDict[Hashable, Tuple[str, Tuple]]" = OrderedDict()
        self._lock = threading.Lock()

    def remember(self, key: Hashable, ends: Tuple, direction: str) -> None:
        with self._lock:
            self._items[key] = (direction, ends)
            self._items.move_to_end(key)
            while len(self._items) > self.limit:
                self._items.popitem(last=False)

    def take(self, key: Hashable, ends: Tuple) -> Optional[str]:
        with self._lock:
            entry = self._items.get(key)
            if entry is None or entry[1] != ends:
                return None
            del self._items[key]
            return entry[0]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


OPEN_CONNECTIONS = _OpenConnections()


def _connection(env: Envelope, g: dict) -> Tuple[Hashable, Tuple]:
    """(key, ends) of the connection a Built or Teardown message is about. Connection ids are
    unique per device; ICMP messages often carry none, so their addresses and ICMP ids stand in."""
    if g.get("fid") is not None or g.get("lid") is not None:  # ICMP: faddr / laddr
        ends = (g.get("fip"), g.get("fid"), g.get("lip"), g.get("lid"))
    else:
        ends = (g.get("fip"), g.get("fport"), g.get("tip"), g.get("tport"))
    key = (env.hostname or "", g["cid"]) if g.get("cid") else (env.hostname or "", "icmp") + ends
    return key, ends


def _address(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """(ip, hostname). With "names" configured the ASA writes an object name such as
    OCSP_Server where the address would be: that is the endpoint's name, not a bad address."""
    if not value:
        return None, None
    try:
        ipaddress.ip_address(value)
        return value, None
    except ValueError:
        return None, value


def _ends(direction: Optional[str], outside: str, inside: str):
    """Which captured end is the source and which the destination.

    The ASA always writes the outside end first. Inbound: outside opened the connection.
    Outbound: inside did. Unknown: neither is assigned (``none_`` captures nothing).
    """
    if direction == "inbound":
        return outside, inside
    if direction == "outbound":
        return inside, outside
    return "none_", "none_"


def detect(env: Envelope) -> bool:
    return bool(_TAG.search(env.message))


def parse(env: Envelope) -> Optional[dict]:
    m = _TAG.search(env.message)
    if not m:
        return None
    family, level, msg_id, text = m.group(1), int(m.group(2)), m.group(3), m.group(4).strip()
    product = "Firepower Threat Defense" if family == "FTD" else "ASA"
    vendor = "Cisco"
    ts = iso_from_formats(env.timestamp, _TS_FORMATS) if env.timestamp else None
    base = dict(timestamp=ts, original_time=env.timestamp, device_hostname=env.hostname,
                severity=SYSLOG_SEVERITY_TEXT.get(level), msg=text, message_id=f"{family}-{level}-{msg_id}")
    vf = {"message_id": msg_id, "level": level, "text": text}

    def net(activity, g, src="s", dst="d", action=None, **extra):
        (sip, shost), (dip, dhost) = _address(g.get(f"{src}ip")), _address(g.get(f"{dst}ip"))
        return event(vendor, product, NETWORK_ACTIVITY, activity, vendor_fields={**vf, **g},
                     src_ip=sip, src_hostname=shost, src_port=to_int(g.get(f"{src}port")),
                     dst_ip=dip, dst_hostname=dhost, dst_port=to_int(g.get(f"{dst}port")),
                     proto=(g.get("proto") or "").lower() or None, action=action, **extra, **base)

    def auth(g, ok: bool, activity=AUTH_LOGON, src_ip=None):
        return event(vendor, product, AUTHENTICATION, activity, "Logoff" if activity == AUTH_LOGOFF else "Logon",
                     vendor_fields={**vf, **g}, user=g.get("user"), src_ip=src_ip or g.get("ip") or g.get("sip"),
                     dst_ip=g.get("server") or g.get("dip"), action="success" if ok else "failure",
                     auth_status="success" if ok else "failure", **base)

    if msg_id in ("302013", "302015", "302303"):
        g = RULES["built"].search(text)
        if g:
            g = g.groupdict()
            OPEN_CONNECTIONS.remember(*_connection(env, g), direction=g["dir"])
            src, dst = _ends(g["dir"], "f", "t")
            return net(NA_OPEN, g, src, dst, action="allow", connection_id=g["cid"], direction=g["dir"])
    if msg_id in ("302014", "302016", "302304"):
        g = RULES["teardown"].search(text)
        if g:
            g = g.groupdict()
            direction = OPEN_CONNECTIONS.take(*_connection(env, g))
            g["direction_source"] = "built message" if direction else "not seen"
            src, dst = _ends(direction, "f", "t")
            return net(NA_CLOSE, g, src, dst, action="allow", connection_id=g["cid"], direction=direction,
                       bytes_total=to_int(g.get("bytes")), close_reason=g.get("reason"))
    if msg_id in ("302020", "302021"):
        g = RULES["icmp"].search(text)
        if g:
            g = g.groupdict()
            key, ends = _connection(env, g)
            if g["verb"] == "Built":
                direction = g.get("dir")
                if direction:
                    OPEN_CONNECTIONS.remember(key, ends, direction=direction)
            else:
                direction = OPEN_CONNECTIONS.take(key, ends)
                g["direction_source"] = "built message" if direction else "not seen"
            src, dst = _ends(direction, "f", "l")
            g["proto"] = "icmp"
            return net(NA_OPEN if g["verb"] == "Built" else NA_CLOSE, g, src, dst, action="allow",
                       connection_id=g.get("cid"), direction=direction)
    if msg_id in ("302017", "302018"):
        g = RULES["gre"].search(text)
        if g:
            g = g.groupdict()
            g["proto"] = "gre"
            return net(NA_OPEN if g["verb"] == "Built" else NA_CLOSE, g, action="allow",
                       connection_id=g["cid"], bytes_total=to_int(g.get("bytes")))
    if msg_id in ("305011", "305012"):
        g = RULES["nat"].search(text)
        if g:  # address translation: the real address is known, the peer is not
            g = g.groupdict()
            return net(NA_OPEN if g["verb"] == "Built" else NA_CLOSE, g, dst="none_", action="allow",
                       nat_ip=g["mip"], nat_port=to_int(g["mport"]))
    if msg_id == "106016":
        g = RULES["spoof"].search(text)
        if g:
            g = g.groupdict()
            return event(vendor, product, DETECTION_FINDING, vendor_fields={**vf, **g}, src_ip=g["sip"],
                         dst_ip=g["dip"], signature="IP spoofing attempt denied", rule_id=msg_id, action="deny", **base)
    if msg_id == "304001":
        g = RULES["url"].search(text)
        if g:
            g = g.groupdict()
            return net(NA_TRAFFIC, g, action="allow", url=g["url"])
    if msg_id == "611103":
        g = RULES["logout"].search(text)
        if g:
            return auth(g.groupdict(), True, AUTH_LOGOFF)
    for rule, ids in (("deny_acl", ("106023",)), ("deny_inbound_tcp", ("106001",)), ("deny_udp", ("106006", "106007")),
                      ("deny_noconn", ("106015",)), ("acl_to_box", ("710003",))):
        if msg_id in ids:
            g = RULES[rule].search(text)
            if g:
                g = g.groupdict()
                return net(NA_REFUSE, g, action="deny", rule=g.get("acl"))
    if msg_id == "106100":
        g = RULES["acl_hit"].search(text)
        if g:
            g = g.groupdict()
            denied = g["verdict"] == "denied"
            return net(NA_REFUSE if denied else NA_TRAFFIC, g, action="deny" if denied else "allow", rule=g["acl"])
    if msg_id.startswith("4000"):
        g = RULES["ips"].search(text)
        if g:
            g = g.groupdict()
            return event(vendor, product, DETECTION_FINDING, vendor_fields={**vf, **g}, src_ip=g["sip"],
                         dst_ip=g["dip"], signature=g["name"], rule_id=g["sid"], **base)
    if msg_id == "733100":
        g = RULES["threat_rate"].search(text)
        if g:
            return event(vendor, product, DETECTION_FINDING, vendor_fields={**vf, **g.groupdict()},
                         signature=f"Threat detection: {g.group('obj')} drop rate exceeded", rule_id=msg_id, **base)
    if msg_id == "113004":
        g = RULES["aaa_ok"].search(text)
        if g:
            return auth(g.groupdict(), True)
    if msg_id in ("113005", "113015"):
        g = RULES["aaa_rejected"].search(text)
        if g:
            return auth(g.groupdict(), False)
    if msg_id in ("113039", "716001", "716002", "722051"):
        g = RULES["anyconnect"].search(text)
        if g:
            g = g.groupdict()
            ended = "terminated" in (g.get("ac") or "", g.get("wv") or "")
            return auth(g, True, AUTH_LOGOFF if ended else AUTH_LOGON)
    if msg_id in ("611101", "611102"):
        g = RULES["user_auth"].search(text)
        if g:
            g = g.groupdict()
            return auth(g, g["res"] == "succeeded")
    if msg_id in ("605004", "605005"):
        g = RULES["mgmt_login"].search(text)
        if g:
            g = g.groupdict()
            return auth(g, g["res"] == "permitted", src_ip=g["sip"])

    return event(vendor, product, BASE_EVENT, vendor_fields=vf, **base)
