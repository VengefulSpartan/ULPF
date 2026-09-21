"""
Syslog envelope splitter.

Perimeter devices wrap their payload in very different syslog headers:
RFC 5424 (Juniper SRX, Check Point Log Exporter), RFC 3164 with or without
a tag (pfSense, Snort, Cisco ASA), RFC 3164 with a year (Cisco ASA), bare
<PRI> followed by key=value (FortiGate, Sophos), or no header at all when a
collector such as rsyslog writes them to a file.

``split_envelope`` separates the header from the vendor payload without
modifying either, so vendor packs only ever look at the payload.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Optional

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) ?")
_BSD_TS = re.compile(
    r"^([A-Z][a-z]{2} {1,2}\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: [A-Z]{3,4})?:? "
)
_ISO_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
)
_HOST = re.compile(r"^([A-Za-z0-9_.:\-]+) ")
_TAG = re.compile(r"^([A-Za-z0-9_./\-]+)(?:\[(\d+)\])?: ?")
_SD_ID = re.compile(r'^[^\s="\]]+$')

SYSLOG_SEVERITY_TEXT = {
    0: "critical", 1: "critical", 2: "critical",
    3: "high", 4: "medium", 5: "low", 6: "informational", 7: "informational",
}


@dataclass
class Envelope:
    raw: str
    message: str
    standard: str = "none"          # rfc5424 | rfc3164 | none
    pri: Optional[int] = None
    facility: Optional[int] = None
    severity: Optional[int] = None
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    app: Optional[str] = None
    procid: Optional[str] = None
    msgid: Optional[str] = None
    sd: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def severity_text(self) -> Optional[str]:
        return SYSLOG_SEVERITY_TEXT.get(self.severity) if self.severity is not None else None


def _parse_structured_data(s: str):
    """Parse RFC 5424 SD-ELEMENTs. Returns (sd_dict, remainder) or None if invalid."""
    sd: Dict[str, Dict[str, str]] = {}
    i, n = 0, len(s)
    while i < n and s[i] == "[":
        j = i + 1
        while j < n and s[j] not in " ]":
            j += 1
        sd_id = s[i + 1:j]
        if not sd_id or not _SD_ID.match(sd_id):
            return None
        params: Dict[str, str] = {}
        while j < n and s[j] == " ":
            j += 1
            k = j
            while j < n and s[j] not in '="] ':
                j += 1
            name = s[k:j]
            if j + 1 >= n or s[j] != "=" or s[j + 1] != '"':
                return None
            j += 2
            val = []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n and s[j + 1] in '"\\]':
                    val.append(s[j + 1])
                    j += 2
                    continue
                val.append(s[j])
                j += 1
            if j >= n:
                return None
            j += 1  # closing quote
            params[name] = "".join(val)
        if j >= n or s[j] != "]":
            return None
        sd[sd_id] = params
        i = j + 1
    return sd, s[i:].lstrip(" ")


def split_envelope(text: str) -> Envelope:
    s = text.rstrip("\r\n")
    env = Envelope(raw=text, message=s)
    rest = s

    m = _PRI.match(rest)
    if m:
        env.pri = int(m.group(1))
        env.facility, env.severity = env.pri >> 3, env.pri & 7
        rest = rest[m.end():]
        if rest.startswith(" ") and not rest.startswith("  "):  # "<14> 2020-01-19T..." (version omitted)
            rest = rest[1:]

    m = _RFC5424.match(rest)
    if m and env.pri is not None:
        env.standard = "rfc5424"
        ts, host, app, procid, msgid = m.groups()
        env.timestamp = None if ts == "-" else ts
        env.hostname = None if host == "-" else host
        env.app = None if app == "-" else app
        env.procid = None if procid == "-" else procid
        env.msgid = None if msgid == "-" else msgid
        rest = rest[m.end():]
        if rest.startswith("- ") or rest == "-":
            rest = rest[2:]
        elif rest.startswith("["):
            parsed = _parse_structured_data(rest)
            if parsed is not None:
                env.sd, rest = parsed
        if rest.startswith("﻿"):
            rest = rest[1:]
        env.message = rest
        return env

    m = _BSD_TS.match(rest) or _ISO_TS.match(rest)
    if m:
        env.standard = "rfc3164"
        env.timestamp = m.group(1)
        rest = rest[m.end():]
        # Cisco ASA may omit the hostname: "<166>Sep 21 2026 10:00:00: %ASA-..."
        if not rest.startswith("%"):
            hm = _HOST.match(rest)
            if hm and "=" not in hm.group(1) and not hm.group(1).endswith(":"):
                env.hostname = hm.group(1)
                rest = rest[hm.end():]
        tm = _TAG.match(rest)
        if tm and not rest.startswith("%"):
            env.app, env.procid = tm.group(1), tm.group(2)
            rest = rest[tm.end():]
    elif env.pri is not None:
        env.standard = "rfc3164"

    env.message = rest
    return env
