"""
Windows Security events in Event XML — the form `wevtutil qe Security /f:xml`, Windows Event
Forwarding and NXLog's xm_xml write, and the most common XML a SOC receives.

The generic XML path (parsing/xmlpairs.py) reads these fields but cannot know what they mean: in a
logon event, EventData's IpAddress is the address the logon came *from*, and nothing in the name
says so. This pack knows, for the events that are authentication:

  4624 logon            4625 failed logon       4634 / 4647 logoff     4648 logon with explicit credentials
  4768 Kerberos TGT     4771 Kerberos pre-auth failed                  4776 NTLM credential validation

Every other event id is kept as a Base Event with its fields, rather than put in a class it may not
belong to.
"""
import re
from typing import Dict, Optional

from backend.services.parsing.xmlpairs import xml_pairs

from .common import AUTH_LOGOFF, AUTH_LOGON, AUTHENTICATION, BASE_EVENT, event, iso_from_formats, to_int
from .envelope import Envelope

NAME = "windows_security"
VENDOR, PRODUCT = "Microsoft", "Windows Security"

_NS = "schemas.microsoft.com/win/2004/08/events/event"
_LOGON, _FAILED, _EXPLICIT = {"4624"}, {"4625", "4771"}, {"4648"}
_LOGOFF = {"4634", "4647"}
_STATUS_CODED = {"4768", "4776"}                 # success or failure is in Status: 0x0 means success
_TITLES = {"4624": "An account was successfully logged on", "4625": "An account failed to log on",
           "4634": "An account was logged off", "4647": "User initiated logoff",
           "4648": "A logon was attempted using explicit credentials",
           "4768": "A Kerberos authentication ticket (TGT) was requested",
           "4771": "Kerberos pre-authentication failed",
           "4776": "The computer attempted to validate the credentials for an account"}
_FRACTION = re.compile(r"(\.\d{6})\d+")          # Windows writes 7 fractional digits; strptime reads 6
_EMPTY = {"", "-", "::1", "0", "null", "NULL"}


def detect(env: Envelope) -> bool:
    msg = env.message
    return "<Event" in msg and (_NS in msg or ("<EventID" in msg and "<System>" in msg))


def _fields(env: Envelope) -> Optional[Dict[str, str]]:
    pairs = xml_pairs(env.message)
    if not pairs:
        return None
    out: Dict[str, str] = {}
    for key, value in pairs:
        short = key.split(".", 1)[1] if key.startswith(("System.", "EventData.")) else key
        out.setdefault(short, value)
    return out


def _address(value: Optional[str]) -> Optional[str]:
    if not value or value in _EMPTY:
        return None
    return value[7:] if value.lower().startswith("::ffff:") else value   # IPv4 written as mapped IPv6


def parse(env: Envelope) -> Optional[dict]:
    f = _fields(env)
    if not f or not f.get("EventID"):
        return None
    event_id = f["EventID"]
    raw_time = f.get("TimeCreated.SystemTime")
    common = dict(
        timestamp=iso_from_formats(_FRACTION.sub(r"\1", raw_time or ""),
                                   ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z")),
        original_time=raw_time, device_hostname=f.get("Computer") or env.hostname,
    )
    user = f.get("TargetUserName")
    auth = event_id in _LOGON | _FAILED | _EXPLICIT | _LOGOFF | _STATUS_CODED
    if not auth:
        return event(VENDOR, PRODUCT, BASE_EVENT, vendor_fields=f, msg=f"Windows event {event_id}", **common)

    if event_id in _STATUS_CODED:
        failed = (f.get("Status") or "0x0").lower() not in ("0x0", "0")
    else:
        failed = event_id in _FAILED
    logoff = event_id in _LOGOFF
    return event(VENDOR, PRODUCT, AUTHENTICATION, AUTH_LOGOFF if logoff else AUTH_LOGON,
                 "Logoff" if logoff else "Logon", vendor_fields=f,
                 user=user if user and user not in _EMPTY else None,
                 src_ip=_address(f.get("IpAddress")),
                 src_port=to_int(f.get("IpPort")) or None,
                 action="failure" if failed else "success", auth_status="failure" if failed else "success",
                 severity="medium" if failed else "informational",
                 msg=_TITLES.get(event_id), rule_id=event_id, **common)
