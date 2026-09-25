"""
Vendor packs: recognise the native log format of widely deployed perimeter
devices and map it to the canonical fields OCSFNormalizer understands.

Each pack exposes NAME, detect(envelope) and parse(envelope). Packs are tried
in order; the first that detects and parses a line wins. Lines no pack claims
fall through to the generic CEF / LEEF / syslog / key=value / JSON parsers.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from . import checkpoint, cisco, fortinet, juniper, paloalto, pfsense, sonicwall, sophos, tracelog, windows
from .envelope import Envelope, split_envelope
from .ids import Snort, Suricata, Zeek

logger = logging.getLogger("tracelog.vendors")

PACKS: List[Any] = [
    paloalto, fortinet, cisco, checkpoint, juniper, sophos, sonicwall, pfsense, Suricata, Zeek, Snort, windows,
    tracelog,   # TRACELOG's own baseline detector findings (backend/services/ml/baseline.py), not a device
]

# Shown in the UI and README compatibility matrix.
SUPPORTED_SOURCES = [
    {"pack": paloalto.NAME, "vendor": "Palo Alto Networks", "product": "PAN-OS (native CSV syslog)",
     "coverage": "TRAFFIC, THREAT mapped; other log types kept as Base Events"},
    {"pack": fortinet.NAME, "vendor": "Fortinet", "product": "FortiGate / FortiOS",
     "coverage": "traffic, UTM (IPS, AV, web filter, app control), VPN and admin login events"},
    {"pack": cisco.NAME, "vendor": "Cisco", "product": "ASA / Firepower Threat Defense",
     "coverage": "connection build/teardown, ACL denies, IPS, threat detection, AAA, AnyConnect, admin login"},
    {"pack": checkpoint.NAME, "vendor": "Check Point", "product": "Quantum gateways via Log Exporter (syslog)",
     "coverage": "firewall, threat prevention blades, identity/auth"},
    {"pack": juniper.NAME, "vendor": "Juniper Networks", "product": "SRX (structured and plain)",
     "coverage": "RT_FLOW create/close/deny, RT_IDP, RT_SCREEN"},
    {"pack": sophos.NAME, "vendor": "Sophos", "product": "Sophos Firewall (SFOS/XG)",
     "coverage": "firewall, IPS/ATP/AV, authentication"},
    {"pack": sonicwall.NAME, "vendor": "SonicWall", "product": "SonicOS",
     "coverage": "connections, IPS/GAV/botnet, admin and user login"},
    {"pack": pfsense.NAME, "vendor": "Netgate / Deciso", "product": "pfSense and OPNsense filterlog",
     "coverage": "IPv4/IPv6 pass/block"},
    {"pack": Suricata.NAME, "vendor": "OISF", "product": "Suricata EVE JSON",
     "coverage": "alerts as findings; flow, DNS, HTTP, TLS and other protocol events"},
    {"pack": Zeek.NAME, "vendor": "Zeek", "product": "Zeek JSON logs", "coverage": "conn and notice logs"},
    {"pack": Snort.NAME, "vendor": "Cisco", "product": "Snort 2 and Snort 3",
     "coverage": "fast and syslog alerts, alert_csv (Snort's columns and pfSense's), Snort 3 alert_json, and "
                 "the header line of a full-format alert"},
    {"pack": windows.NAME, "vendor": "Microsoft", "product": "Windows Security events (Event XML)",
     "coverage": "logon, failed logon, logoff, explicit-credential logon, Kerberos and NTLM authentication; "
                 "other event ids kept as Base Events with their fields"},
    {"pack": "generic_cef", "vendor": "Any", "product": "ArcSight CEF (F5, Imperva, Trend Micro, Check Point, ...)",
     "coverage": "header and standard extension keys"},
    {"pack": "generic_leef", "vendor": "Any", "product": "IBM LEEF 1.0/2.0", "coverage": "header and attributes"},
    {"pack": "generic", "vendor": "Any", "product": "RFC 3164/5424 syslog, key=value, JSON, XML",
     "coverage": "common field names; everything else preserved in unmapped"},
]


def parse_vendor(raw_text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Return (pack_name, parsed_dict) for the first vendor pack that claims the line, else None."""
    env = split_envelope(raw_text)
    for pack in PACKS:
        try:
            if not pack.detect(env):
                continue
            parsed = pack.parse(env)
        except Exception:  # a buggy pack must never lose the event; the generic path still runs
            logger.exception("vendor pack %s failed", getattr(pack, "NAME", pack))
            continue
        if parsed:
            parsed["_pack"] = pack.NAME
            if env.standard != "none":
                parsed.setdefault("syslog", {k: v for k, v in (
                    ("facility", env.facility), ("severity", env.severity), ("hostname", env.hostname),
                    ("app_name", env.app), ("procid", env.procid), ("msgid", env.msgid)) if v is not None})
            return pack.NAME, parsed
    return None


__all__ = ["PACKS", "SUPPORTED_SOURCES", "Envelope", "parse_vendor", "split_envelope"]
