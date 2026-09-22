"""Shared helpers for vendor packs."""
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, Optional

# OCSF class ids emitted by vendor packs (see OCSFNormalizer.CLASS_INFO)
NETWORK_ACTIVITY = 4001
AUTHENTICATION = 3002
DETECTION_FINDING = 2004
BASE_EVENT = 0

# OCSF Network Activity activity ids
NA_OPEN, NA_CLOSE, NA_RESET, NA_FAIL, NA_REFUSE, NA_TRAFFIC = 1, 2, 3, 4, 5, 6
NA_NAMES = {1: "Open", 2: "Close", 3: "Reset", 4: "Fail", 5: "Refuse", 6: "Traffic"}
# OCSF Authentication activity ids
AUTH_LOGON, AUTH_LOGOFF = 1, 2

IANA_PROTOCOLS = {
    "1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "41": "ipv6", "47": "gre",
    "50": "esp", "51": "ah", "58": "ipv6-icmp", "89": "ospf", "132": "sctp",
}

_KV = re.compile(r'([A-Za-z0-9_.@\-]+)=("(?:[^"\\]|\\.)*"|\S*)')

DENY_WORDS = ("deny", "denied", "drop", "dropped", "block", "blocked", "reject", "refuse", "prevent", "reset")


def parse_kv(text: str) -> Dict[str, str]:
    """key=value / key="quoted value" parser that keeps the vendor's own key names."""
    out: Dict[str, str] = {}
    for k, v in _KV.findall(text):
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def proto_name(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    s = str(value).strip().lower()
    return IANA_PROTOCOLS.get(s, s)


def to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return None if s in ("", "-", "N/A", "n/a", "None", "none") else s


def iso_from_formats(value: Optional[str], formats: Iterable[str], tz_offset: Optional[str] = None) -> Optional[str]:
    """Parse a vendor timestamp and return ISO 8601. Naive times get tz_offset (e.g. '+0530') or UTC."""
    if not value:
        return None
    text = re.sub(r"\s+", " ", value.strip())  # "Sep  1" (two spaces) is how syslog pads single-digit days
    now = datetime.now(timezone.utc)
    for fmt in formats:
        yearless = "%Y" not in fmt and "%y" not in fmt and "%s" not in fmt
        try:
            # a timestamp without a year (BSD syslog "Sep 20 14:00:15") is parsed with the current year
            # attached, so it is not dated 1900 and Feb 29 parses in a leap year
            dt = datetime.strptime(f"{now.year} {text}", f"%Y {fmt}") if yearless else datetime.strptime(text, fmt)
        except ValueError:
            continue
        if yearless and dt.replace(tzinfo=timezone.utc) > now + timedelta(days=2):
            dt = dt.replace(year=now.year - 1)  # a December line read in January
        if dt.tzinfo is None:
            tz = timezone.utc
            if tz_offset:
                m = re.match(r"^([+-])(\d{2}):?(\d{2})$", tz_offset.strip())
                if m:
                    delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
                    tz = timezone(delta if m.group(1) == "+" else -delta)
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc).isoformat()
    return None


def iso_from_epoch(value: Any) -> Optional[str]:
    """Epoch in s, ms, us or ns -> ISO 8601 UTC."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    while v > 1e11:  # scale ms/us/ns down to seconds
        v /= 1000.0
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def is_denied(action: Optional[str]) -> bool:
    return bool(action) and any(w in action.lower() for w in DENY_WORDS)


def event(vendor: str, product: str, ocsf_class: int, activity_id: Optional[int] = None,
          activity_name: Optional[str] = None, vendor_fields: Optional[Dict[str, Any]] = None,
          **canonical: Any) -> Dict[str, Any]:
    """
    Build the dict handed to OCSFNormalizer. Canonical keys (src_ip, dst_port,
    action, user, severity, signature, ...) are the normaliser's field names.
    Everything the device sent is kept under ``vendor_fields`` so it lands in
    OCSF ``unmapped`` without colliding with canonical names.
    """
    out: Dict[str, Any] = {"vendor": vendor, "product": product, "_ocsf_class": ocsf_class}
    if activity_id is not None:
        out["_activity_id"] = activity_id
        out["_activity_name"] = activity_name or (NA_NAMES.get(activity_id) if ocsf_class == NETWORK_ACTIVITY else None)
    for k, v in canonical.items():
        if v is not None and v != "":
            out[k] = v
    if vendor_fields:
        out["vendor_fields"] = {k: v for k, v in vendor_fields.items() if v not in (None, "")}
    return out
