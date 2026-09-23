"""
Evidence-based field inference for logs no vendor pack or learned parser recognises.

The rule is precision over recall: a field is filled only when there is evidence for
both what the field means and that its value is valid. Everything else stays in the
event's unmapped section, and the event says it is unverified and why each field was
chosen. A SIEM can trust what is filled; what is missing is filled later by a parser
learned from many samples (Parser Studio).

Evidence used:
  key meaning   "source-ip", "srcIP", "ip_client", "SRC", "event.clientip" all mean source address
  value check   an address field must hold an IP, a port 0-65535, a time must parse and be plausible
  direction     "a:p -> b:q", "from a to b" give source and destination without key names
  syslog header timestamp, host and the RFC 5424 / 3164 severity (0 = emergency ... 7 = debug)

Two IP addresses with nothing saying which is the source are NOT assigned: guessing
from their order is exactly how a parser ends up confidently wrong.
"""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from backend.services import timefmt
from backend.services.vendors.common import (
    BASE_EVENT, DETECTION_FINDING, IANA_PROTOCOLS, NA_REFUSE, NA_TRAFFIC, NETWORK_ACTIVITY, AUTHENTICATION, event,
)
from backend.services.vendors.envelope import Envelope, SYSLOG_SEVERITY_TEXT, split_envelope

THRESHOLD = 0.7  # minimum confidence to fill a field
PACK = "generic_inferred"
STANDARD_PACKS = {"cef": "generic_cef", "leef": "generic_leef"}   # names listed in vendors.SUPPORTED_SOURCES

# ---------------------------------------------------------------------------------------------
# key meaning
# ---------------------------------------------------------------------------------------------
SRC_WORDS = {"src", "source", "client", "orig", "origin", "originator", "sender", "attacker", "initiator",
             "from", "s", "c", "caller"}
DST_WORDS = {"dst", "dest", "destination", "server", "resp", "responder", "target", "recipient", "victim",
             "to", "d", "callee"}
ADDR_WORDS = {"ip", "addr", "address", "ipaddr", "ipaddress", "ipv4", "ipv6", "host"}
PORT_WORDS = {"port", "pt"}
SKIP_WORDS = {"nat", "xlate", "translated", "mapped", "post", "pre", "mac", "zone", "if", "intf", "interface",
              "iface", "country", "loc", "location", "geo", "asn", "name", "user", "vlan", "bytes", "packets",
              "pkts", "mask", "net", "subnet", "gateway", "gw", "management", "mgmt"}
GLUED = sorted(SRC_WORDS | DST_WORDS | ADDR_WORDS | PORT_WORDS | {"proto", "nat", "mac", "user", "name", "time",
                                                                  "bytes", "if", "zone"}, key=len, reverse=True)

EXACT = {  # well-known field names across CEF, iptables, Zeek, ECS and common vendors
    "src": "src_ip", "srcip": "src_ip", "src_ip": "src_ip", "saddr": "src_ip", "sourceaddress": "src_ip",
    "dst": "dst_ip", "dstip": "dst_ip", "dst_ip": "dst_ip", "daddr": "dst_ip", "destinationaddress": "dst_ip",
    "spt": "src_port", "sport": "src_port", "srcport": "src_port", "src_port": "src_port",
    "sourceport": "src_port", "dpt": "dst_port", "dport": "dst_port", "dstport": "dst_port",
    "dst_port": "dst_port", "destinationport": "dst_port",
    "id.orig_h": "src_ip", "id.resp_h": "dst_ip", "id.orig_p": "src_port", "id.resp_p": "dst_port",
    "proto": "protocol", "protocol": "protocol", "ipproto": "protocol", "ip_proto": "protocol",
    "transport": "protocol",
    "act": "action", "action": "action", "disposition": "action", "decision": "action", "verdict": "action",
    "fw_action": "action", "policy_action": "action",
    "suser": "user", "user": "user", "username": "user", "usrname": "user", "user_name": "user", "login": "user",
    "account": "user", "duser": "user",
    "rt": "time", "timestamp": "time", "time": "time", "ts": "time", "datetime": "time", "date_time": "time",
    "eventtime": "time", "event_time": "time", "start_time": "time", "starttime": "time", "start": "time",
    "devtime": "time", "logtime": "time", "generated_time": "time",
    "severity": "severity", "sev": "severity", "level": "severity", "priority": "severity",
    "signature": "signature", "sig": "signature", "attack": "signature", "attack_type": "signature",
    "attack_name": "signature", "threat": "signature", "threat_name": "signature", "threatname": "signature",
    "virus": "signature", "virus_name": "signature", "malware": "signature", "ids_signature": "signature",
}
WEAK_ACTION_KEYS = {"status", "result", "outcome", "request_status", "info", "event_action", "fw_rule_action"}
NOT_TIME = {"elapsed", "duration", "timezone", "tz", "ttl", "timeout", "time_taken", "response_time", "delay",
            "uptime", "runtime", "wait"}

ALLOW = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "passed", "built", "forward",
         "forwarded", "open", "opened", "established"}
DENY = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "refuse", "refused",
        "reset", "discard", "discarded", "prevent", "prevented", "quarantine", "quarantined", "tcp_denied"}
SEVERITY_TEXT = {
    "emergency": "Critical", "emerg": "Critical", "alert": "Critical", "critical": "Critical", "crit": "Critical",
    "fatal": "Critical", "very-high": "Critical", "high": "High", "error": "High", "err": "High", "major": "High",
    "medium": "Medium", "warning": "Medium", "warn": "Medium", "moderate": "Medium", "minor": "Low",
    "low": "Low", "notice": "Low", "informational": "Informational", "information": "Informational",
    "info": "Informational", "debug": "Informational",
}
PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "esp", "ah", "sctp", "igmp", "ospf"}
_NOT_USERS = {"-", "n/a", "na", "none", "null", "unknown", "success", "succeeded", "failure", "failed", "fail",
              "true", "false", "yes", "no", "ok", "0", "1"} | ALLOW | DENY
AUTH_WORDS = re.compile(r"\b(log ?in|log ?on|logon|login|auth\w*|sign-?in|password|sslvpn|vpn)\b", re.I)


@lru_cache(maxsize=4096)
def key_words(key: str) -> List[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)          # camelCase
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)        # IPAddress
    words: List[str] = []
    for w in re.split(r"[\s_\-./:@\[\]]+", s.lower()):
        if not w:
            continue
        rest, parts = w, []
        while rest:  # split glued words: clientip -> client ip, srcport -> src port
            for g in GLUED:
                if rest.startswith(g) and len(rest) > len(g):
                    parts.append(g)
                    rest = rest[len(g):]
                    break
            else:
                parts.append(rest)
                rest = ""
        # a split counts only when every piece is a known word. Accepting any remainder read
        # "device" as d + evice, and "d" means destination: device_ip became a destination address,
        # sensor_ip and system_ip source addresses, EventData.IpAddress a destination. Those are the
        # wrong fields this parser exists not to produce.
        words += parts if all(p in GLUED for p in parts) else [w]
    return words


@lru_cache(maxsize=4096)
def key_role(key: str) -> Tuple[Optional[str], float, str]:
    """(role, confidence, reason) for a field name. Cached: a format sends the same names every line."""
    k = key.strip()
    low = k.lower()
    last = low.split(".")[-1]
    for cand in (low, last):
        if cand in EXACT:
            return EXACT[cand], 0.95, f"'{key}' is a standard name for {EXACT[cand].replace('_', ' ')}"
    if low in WEAK_ACTION_KEYS or last in WEAK_ACTION_KEYS:
        return "action", 0.75, f"'{key}' often carries the action; accepted only with an action word"
    words = set(key_words(k))
    if words & SKIP_WORDS:
        return None, 0.0, ""
    src, dst = bool(words & SRC_WORDS), bool(words & DST_WORDS)
    if src != dst:
        side = "src" if src else "dst"
        if words & PORT_WORDS:
            return f"{side}_port", 0.85, f"'{key}' names the {'source' if src else 'destination'} port"
        if words & ADDR_WORDS or len(words) == 1:
            return f"{side}_ip", 0.85, f"'{key}' names the {'source' if src else 'destination'} address"
    if words & {"time", "timestamp", "date", "datetime"} and not words & NOT_TIME:
        return "time", 0.8, f"'{key}' names a time"
    if words & {"severity", "sev", "priority", "level", "criticality"}:
        return "severity", 0.8, f"'{key}' names a severity"
    if words & {"user", "username", "login", "account"} and not words & {"agent", "useragent"}:
        return "user", 0.8, f"'{key}' names a user"
    if words & {"signature", "attack", "threat", "virus", "malware", "exploit"}:
        return "signature", 0.8, f"'{key}' names a threat or attack"
    return None, 0.0, ""


# ---------------------------------------------------------------------------------------------
# value checks
# ---------------------------------------------------------------------------------------------
def as_ip(v: Any) -> Optional[str]:
    s = str(v).strip().strip("[]")
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def as_port(v: Any) -> Optional[int]:
    s = str(v).strip()
    if s.isdigit() and 0 <= int(s) <= 65535:
        return int(s)
    return None


def as_protocol(v: Any) -> Optional[str]:
    s = str(v).strip().lower()
    if s.isdigit():
        name = IANA_PROTOCOLS.get(s)
        return name.upper() if name else None
    return s.upper() if s in PROTOCOLS else None


def as_action(v: Any) -> Optional[str]:
    s = str(v).strip().lower().rstrip(".")
    words = set(re.split(r"[^a-z_]+", s)) - {""}
    allow, deny = bool(words & ALLOW), bool(words & DENY)
    if allow == deny:
        return None
    return "allowed" if allow else "denied"


def as_severity(v: Any) -> Optional[str]:
    return SEVERITY_TEXT.get(str(v).strip().lower())


_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                 "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                 "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%a %b %d %H:%M:%S %Y", "%b %d %Y %H:%M:%S",
                 "%d-%b-%Y %H:%M:%S", "%Y:%m:%d-%H:%M:%S", "%m/%d/%Y %H:%M:%S")
_YEARLESS = ("%b %d %H:%M:%S", "%b %d %H:%M:%S.%f")


def _plausible(dt: datetime) -> bool:
    now = datetime.now(timezone.utc)
    return datetime(2000, 1, 1, tzinfo=timezone.utc) <= dt <= now + timedelta(days=2)


def as_time(v: Any, allow_epoch: bool = True) -> Optional[str]:
    s = str(v).strip()
    if not s:
        return None
    if allow_epoch and re.fullmatch(r"\d{10}(\.\d+)?|\d{13}|\d{16}|\d{19}", s):
        n = float(s)
        n = n / 1e9 if n > 1e17 else n / 1e6 if n > 1e14 else n / 1e3 if n > 1e11 else n
        dt = datetime.fromtimestamp(n, tz=timezone.utc)
        return dt.isoformat() if _plausible(dt) else None
    s2 = re.sub(r"\s+", " ", s)
    # the format that read this shape of timestamp before is tried first (backend/services/timefmt.py)
    hit = timefmt.parse_first(s2, _TIME_FORMATS, lambda fmt: datetime.strptime(s2, fmt))
    if hit:
        dt = hit[1]
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat() if _plausible(dt) else None
    hit = timefmt.parse_first(s2, _YEARLESS, lambda fmt: datetime.strptime(s2, fmt))
    if hit:
        now = datetime.now(timezone.utc)
        dt = hit[1].replace(year=now.year, tzinfo=timezone.utc)
        if dt > now + timedelta(days=2):  # a December line read in January
            dt = dt.replace(year=now.year - 1)
        return dt.isoformat()
    return None


def as_user(v: Any) -> Optional[str]:
    s = str(v).strip()
    return s if s and not as_ip(s) and s.lower() not in _NOT_USERS and not s.isdigit() else None


def as_signature(v: Any) -> Optional[str]:
    s = str(v).strip()
    return s if s and not s.isdigit() else None


# what a value must look like to be accepted for each field
VALUE_CHECKS = {"src_ip": as_ip, "dst_ip": as_ip, "src_port": as_port, "dst_port": as_port, "protocol": as_protocol,
                "action": as_action, "severity": as_severity, "time": as_time, "user": as_user,
                "signature": as_signature}
ROLES = tuple(VALUE_CHECKS)


# ---------------------------------------------------------------------------------------------
# structure
# ---------------------------------------------------------------------------------------------
_KEY_BEFORE_EQ = re.compile(r"([A-Za-z_][A-Za-z0-9_.@\-]*)\s*=\s*(.*)$", re.S)
_WS_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_.@\-]*)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s"\']*)')
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IP = rf"(?:{_IPV4}|\[?[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+\]?)"
_ARROW = re.compile(rf"({_IPV4})(?:[:/](\d{{1,5}}))?\s*(?:->|=>|-->|→|>)\s*({_IPV4})(?:[:/](\d{{1,5}}))?")
_FROM_TO = re.compile(rf"\bfrom\s+({_IPV4})(?:[:/](\d{{1,5}}))?.{{0,40}}?\bto\s+({_IPV4})(?:[:/](\d{{1,5}}))?", re.I)
_BARE_IP = re.compile(rf"(?<![\w.:]){_IPV4}(?![\w.])")


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _split_respecting_quotes(s: str, delim: str) -> List[str]:
    out, cur, q = [], [], None
    for ch in s:
        if q:
            cur.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur.append(ch)
        elif ch == delim:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _flatten(obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        if obj and all(not isinstance(x, (dict, list)) for x in obj):
            out.append((prefix, ", ".join(str(x) for x in obj)))
    else:
        out.append((prefix, obj))
    return out


def structure(body: str) -> Dict[str, Any]:
    """kind: json | cef | leef | kv | delimited | text, with key/value pairs and the free text left over."""
    b = body.strip()
    if b.startswith("{") and b.endswith("}"):
        try:
            return {"kind": "json", "delimiter": None, "pairs": _flatten(json.loads(b)), "text": "", "prefix": ""}
        except ValueError:
            pass
    for tag, kind in (("CEF:", "cef"), ("LEEF:", "leef")):
        if tag in b:
            from backend.services.parsing.cef_parser import CEFParser
            from backend.services.parsing.leef_parser import LEEFParser
            ok, d = (CEFParser if kind == "cef" else LEEFParser).parse(b[b.index(tag):])
            if ok:
                pairs = [(k, v) for k, v in d.items() if not k.startswith("_")]
                return {"kind": kind, "delimiter": None, "pairs": pairs, "text": b[:b.index(tag)], "prefix": ""}
    for delim in ("|", ";", ",", "\t"):
        if b.count(delim) < 2:
            continue
        pieces = _split_respecting_quotes(b, delim)
        pairs, prefix = [], ""
        for i, piece in enumerate(pieces):
            m = _KEY_BEFORE_EQ.search(piece) if "=" in piece else None
            if not m:
                continue
            key_start = m.start(1)
            if i == 0 and key_start > 0:
                prefix = piece[:key_start]
            elif key_start > 0 and piece[:key_start].strip():
                continue  # "=" inside free text
            val = _unquote(m.group(2))
            if i == len(pieces) - 1 and len(val) > 1 and val.endswith(".") and not as_ip(val[:-1]):
                val = val[:-1]  # sentence-ending full stop after the last value
            pairs.append((m.group(1), val))
        if len(pairs) >= 3 and len(pairs) >= 0.6 * len(pieces):
            return {"kind": "kv", "delimiter": delim, "pairs": pairs, "text": prefix, "prefix": prefix}
    matches = list(_WS_KV.finditer(b))
    if len(matches) >= 2:
        pairs = [(m.group(1), _unquote(m.group(2))) for m in matches]
        text = _WS_KV.sub(" ", b)
        prefix = b[:matches[0].start()]
        return {"kind": "kv", "delimiter": " ", "pairs": pairs, "text": text, "prefix": prefix}
    for delim in ("\t", ","):
        if b.count(delim) >= 4:
            return {"kind": "delimited", "delimiter": delim, "pairs": [], "text": b, "prefix": "",
                    "columns": _split_respecting_quotes(b, delim)}
    return {"kind": "text", "delimiter": None, "pairs": [], "text": b, "prefix": ""}


# ---------------------------------------------------------------------------------------------
# format fingerprint: lines of the same format get the same id, whatever their values
# ---------------------------------------------------------------------------------------------
_SUBS = [
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<Q>"),
    (re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+"), "<URL>"),
    (re.compile(rf"(?<![\d.]){_IPV4}(?![\d.])"), "<IP>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "<MAC>"),
    (re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"), "<HOST>"),
    (re.compile(r"\b0x[0-9A-Fa-f]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]*\d[0-9a-fA-F]*[a-fA-F][0-9a-fA-F]*\b|\b[0-9a-fA-F]*[a-fA-F][0-9a-fA-F]*\d[0-9a-fA-F]*\b"),
     "<X>"),
    (re.compile(r"\d+"), "<N>"),
]


def _mask(text: str) -> str:
    for rx, rep in _SUBS:
        text = rx.sub(rep, text)
    return text


def _mask_word(tok: str) -> str:
    low = tok.lower().strip(",.:;()[]")
    if low in ALLOW or low in DENY:
        return "<ACTION>"
    if low in PROTOCOLS:
        return "<PROTO>"
    return tok


def tokens(text: str) -> List[str]:
    """Whitespace tokens; a double-quoted run stays one token."""
    return re.findall(r'(?:[^\s"]|"[^"]*"?)+', text)


def mask_token(tok: str) -> str:
    return _mask_word(_mask(tok))


TEXT_TOKENS = 24      # tokens of a free-text message that decide its format
MAX_KEYS = 14


def fingerprint(st: Dict[str, Any], env: Envelope) -> Dict[str, Any]:
    """
    The line's format, from its structure and never from its values: lines of one format get
    the same id whatever addresses, ports, users or times they carry.
      key=value, JSON, CEF, LEEF   kind, delimiter, app and the key names
      delimited (CSV, TSV)         delimiter, number of columns and app
      free text                    app and the message's tokens with values masked
                                   (<IP>, <N>, <HOST>, <ACTION>, <PROTO>, ...)
    """
    app = re.sub(r"\d+", "<N>", env.app or "")
    if st["kind"] in ("kv", "json", "cef", "leef"):
        keys = [k for k, _ in st["pairs"]][:MAX_KEYS]
        template = f"{st['kind']}{' (' + repr(st['delimiter']) + ')' if st['delimiter'] else ''} keys: " \
                   f"{', '.join(keys)}"
        basis = f"{st['kind']}|{st['delimiter']}|{app}|{'|'.join(k.lower() for k in keys)}"
        size = len(st["pairs"])
    elif st["kind"] == "delimited":
        cols = [mask_token(c.strip()) or "''" for c in st["columns"]]
        template = st["delimiter"].join(cols)
        basis = f"delimited|{st['delimiter']}|{len(cols)}|{app}"
        size = len(cols)
    else:
        toks = [mask_token(t) for t in tokens(st["text"])][:TEXT_TOKENS]
        template = " ".join(toks)
        basis = f"text|{app}|{template}"
        size = len(toks)

    return {"format_id": hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12], "template": template[:600],
            "kind": st["kind"], "delimiter": st["delimiter"], "app": app, "size": size}


# ---------------------------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------------------------
def _cef_severity(v: Any) -> Optional[str]:
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        return "Low" if n <= 3 else "Medium" if n <= 6 else "High" if n <= 8 else "Critical"
    return as_severity(s)


def syslog_severity_label(sev: int) -> Optional[str]:
    """OCSF severity label for a syslog PRI severity (0 = emergency ... 7 = debug)."""
    text = SYSLOG_SEVERITY_TEXT.get(sev)
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
            "informational": "Informational"}.get(text) if text else None


def infer(raw_text: str, env: Optional[Envelope] = None, st: Optional[Dict[str, Any]] = None
          ) -> Tuple[str, Dict[str, Any]]:
    env = env or split_envelope(raw_text)
    st = st or structure(env.message)
    fields: Dict[str, Tuple[Any, float, str]] = {}   # role -> (value, confidence, evidence)
    rejected: List[str] = []

    def offer(role: str, value: Any, conf: float, why: str) -> None:
        cur = fields.get(role)
        if cur and cur[0] != value and abs(cur[1] - conf) < 0.05:
            fields[role] = (cur[0], min(cur[1], conf) - 0.3, cur[2] + f"; conflicts with {why}")
        elif not cur or conf > cur[1]:
            fields[role] = (value, conf, why)

    checks = VALUE_CHECKS
    for key, value in st["pairs"]:
        if value is None or str(value).strip() in ("", "-"):
            continue
        if st["kind"] == "cef" and key == "severity_raw":
            sev = _cef_severity(value)
            if sev:
                offer("severity", sev, 0.9, f"CEF header severity {value}")
            continue
        if st["kind"] == "cef" and key == "event_name":
            continue
        role, conf, why = key_role(key)
        if not role:
            continue
        checked = checks[role](value)
        if checked is None:
            rejected.append(f"'{key}'='{str(value)[:40]}' looks like {role.replace('_', ' ')} but the value is not valid")
            continue
        offer(role, checked, conf, why + f"; value '{str(value)[:40]}' is valid")

    text = st.get("text") or ""
    if st["kind"] in ("text", "delimited"):
        text = st["text"]
    for rx, conf, how in ((_ARROW, 0.9, "arrow"), (_FROM_TO, 0.85, "'from ... to ...'")):
        m = rx.search(text)
        if m and as_ip(m.group(1)) and as_ip(m.group(3)):
            offer("src_ip", as_ip(m.group(1)), conf, f"left of the {how} in '{m.group(0)[:60]}'")
            offer("dst_ip", as_ip(m.group(3)), conf, f"right of the {how} in '{m.group(0)[:60]}'")
            if m.group(2) and as_port(m.group(2)) is not None:
                offer("src_port", as_port(m.group(2)), conf, f"port after the source address in '{m.group(0)[:60]}'")
            if m.group(4) and as_port(m.group(4)) is not None:
                offer("dst_port", as_port(m.group(4)), conf, f"port after the destination address in "
                                                            f"'{m.group(0)[:60]}'")
            break
    words = [w for w in re.split(r"[^A-Za-z0-9_\-]+", text) if w]
    lower = {w.lower() for w in words}
    if "protocol" not in fields:
        protos = {w for w in lower if w in PROTOCOLS}
        if len(protos) == 1:
            offer("protocol", protos.pop().upper(), 0.8, "the only protocol name in the message")
    if "action" not in fields:
        a, d = lower & ALLOW, lower & DENY
        if bool(a) != bool(d) and not {"built", "open", "opened"} >= (a or d):
            offer("action", "allowed" if a else "denied", 0.75,
                  f"the message says '{sorted(a or d)[0]}' and no opposite action word")
    observed_ips = sorted({ip for ip in _BARE_IP.findall(text) if as_ip(ip)} -
                          {fields.get("src_ip", (None,))[0], fields.get("dst_ip", (None,))[0]})

    # time: a keyed time, else the syslog header, else none (the event then says it used arrival time)
    if "time" not in fields and env.timestamp:
        t = as_time(env.timestamp)
        if t:
            offer("time", t, 0.9, f"syslog header timestamp '{env.timestamp}'")
    if "time" not in fields:  # a timestamp opening the message: "2026:09:21-10:00:00 utm ...", "1789984800.123 ..."
        toks = env.message.split()
        for cand in (" ".join(toks[:2]), toks[0] if toks else ""):
            t = as_time(cand) if cand else None
            if t:
                offer("time", t, 0.75, f"timestamp '{cand}' at the start of the message")
                break
    # severity: a keyed textual severity, else the syslog header's (RFC 5424: 0 = emergency ... 7 = debug)
    if "severity" not in fields and env.severity is not None:
        offer("severity", syslog_severity_label(env.severity), 0.9,
              f"syslog header severity {env.severity} (0 = emergency ... 7 = debug)")

    chosen = {r: v for r, v in fields.items() if v[1] >= THRESHOLD}
    below = {r: v for r, v in fields.items() if v[1] < THRESHOLD}
    # an endpoint needs its address: a port alone is kept in unmapped, not half an endpoint
    for side in ("src", "dst"):
        if f"{side}_port" in chosen and f"{side}_ip" not in chosen:
            below[f"{side}_port"] = chosen.pop(f"{side}_port")

    has_ip = "src_ip" in chosen or "dst_ip" in chosen
    if "signature" in chosen:
        cls = DETECTION_FINDING
    elif "user" in chosen and AUTH_WORDS.search(env.message):
        cls = AUTHENTICATION
    elif has_ip:
        cls = NETWORK_ACTIVITY
    elif observed_ips and ("protocol" in chosen or "action" in chosen) and not AUTH_WORDS.search(env.message):
        # addresses plus a protocol or an allow/deny: network traffic, even though the line does not say which
        # address is the source; the endpoints stay empty and the addresses are listed as unassigned
        cls = NETWORK_ACTIVITY
    else:
        cls = BASE_EVENT
    activity = (NA_REFUSE if chosen.get("action", (None,))[0] == "denied" else NA_TRAFFIC) \
        if cls == NETWORK_ACTIVITY else None

    confidence = round(sum(v[1] for v in chosen.values()) / len(chosen), 2) if chosen else 0.0
    vendor, product = "Unknown", "Unknown format"
    if st["kind"] in ("cef", "leef"):
        d = dict(st["pairs"])
        vendor, product = str(d.get("vendor") or vendor), str(d.get("product") or product)
    canonical = {r: v[0] for r, v in chosen.items()}
    if "time" in canonical:
        canonical["timestamp"] = canonical.pop("time")
    vendor_fields = {k: v for k, v in st["pairs"]}
    if st.get("prefix", "").strip():
        vendor_fields["_message_prefix"] = st["prefix"].strip()
    if st["kind"] in ("text", "delimited") or (st.get("text") or "").strip():
        vendor_fields["_message_text"] = (st.get("text") or "").strip()[:2000]
    out = event(vendor, product, cls, activity, None, vendor_fields,
                device_hostname=env.hostname, **canonical)
    # CEF and LEEF define their own key names (src, dst, spt, dpt, act, suser, ...): fields read from them follow the
    # standard, not an inference, so these lines count as parsed by a known format and never as "new formats"
    standard = STANDARD_PACKS.get(st["kind"])
    pack = standard or PACK
    out["_pack"] = pack
    fp = fingerprint(st, env)
    out["tracelog_parse"] = {
        "parser": f"{st['kind'].upper()} standard keys" if standard else f"generic ({st['kind']})",
        "verified": bool(standard), "standard": st["kind"].upper() if standard else None, "confidence": confidence,
        "format_id": fp["format_id"], "template": fp["template"],
        "structure": {"kind": st["kind"], "delimiter": st["delimiter"], "app": fp["app"], "size": fp["size"]},
        "fields": {r: {"value": v[0], "confidence": round(v[1], 2), "why": v[2]} for r, v in chosen.items()},
        "not_filled": {r: {"value": v[0], "confidence": round(max(v[1], 0), 2), "why": v[2]} for r, v in below.items()},
        "rejected_values": rejected[:20],
        "unassigned_ips": observed_ips[:10],
        "time_source": "device" if "time" in chosen else "received",
    }
    return pack, out
