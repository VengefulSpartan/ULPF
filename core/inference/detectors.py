import re
import ipaddress
from typing import Tuple, Optional, List, Dict
from datetime import datetime

# Regex Patterns
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
MAC_REGEX = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})$")
HASH_REGEX = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
FQDN_REGEX = re.compile(r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$")
ISO8601_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
SYSLOG_TS_REGEX = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}$")

KNOWN_ACTIONS = {"allow", "deny", "drop", "block", "accept", "reject", "permit", "reset", "pass", "quarantine"}
KNOWN_SEVERITIES = {"info", "informational", "warn", "warning", "error", "err", "crit", "critical", "debug", "fatal", "emerg", "emergency", "notice"}
COMMON_USERS = {"root", "admin", "administrator", "system", "guest", "user", "daemon", "service", "sysadmin"}


def detect_ipv4(val: str) -> float:
    if IPV4_REGEX.match(val):
        try:
            ipaddress.IPv4Address(val)
            return 1.0
        except ValueError:
            pass
    return 0.0


def detect_ipv6(val: str) -> float:
    if ":" in val:
        try:
            ipaddress.IPv6Address(val)
            return 1.0
        except ValueError:
            pass
    return 0.0


def detect_mac(val: str) -> float:
    return 1.0 if MAC_REGEX.match(val) else 0.0


def detect_port(val: str) -> float:
    if val.isdigit():
        num = int(val)
        if 1 <= num <= 65535:
            # High confidence if port looks non-year
            if num not in (2024, 2025, 2026, 2027):
                return 0.85
            return 0.50
    return 0.0


def detect_timestamp(val: str) -> float:
    if ISO8601_REGEX.match(val) or SYSLOG_TS_REGEX.match(val):
        return 1.0
    if val.isdigit() and len(val) in (10, 13):
        # Epoch timestamp
        try:
            ts = float(val) / (1000 if len(val) == 13 else 1)
            if 1500000000 <= ts <= 2000000000:
                return 0.90
        except ValueError:
            pass
    return 0.0


def detect_url(val: str) -> float:
    return 1.0 if URL_REGEX.match(val) else 0.0


def detect_fqdn(val: str) -> float:
    if FQDN_REGEX.match(val) and not detect_ipv4(val):
        return 0.90
    return 0.0


def detect_hostname(val: str) -> float:
    if val.isalnum() or "-" in val or "_" in val:
        if not val.isdigit() and len(val) <= 64:
            return 0.60
    return 0.0


def detect_hash(val: str) -> float:
    return 1.0 if HASH_REGEX.match(val) else 0.0


def detect_action(val: str) -> float:
    cleaned = val.lower().strip('"\'')
    if cleaned in KNOWN_ACTIONS:
        return 1.0
    return 0.0


def detect_severity(val: str) -> float:
    cleaned = val.lower().strip('"\'')
    if cleaned in KNOWN_SEVERITIES:
        return 0.95
    return 0.0


def detect_username(val: str) -> float:
    cleaned = val.lower().strip('"\'')
    if cleaned in COMMON_USERS:
        return 0.95
    return 0.0


def detect_integer(val: str) -> float:
    if val.lstrip("-").isdigit():
        return 0.70
    return 0.0


def detect_ip_port(val: str) -> float:
    if ":" in val:
        parts = val.split(":")
        if len(parts) == 2 and detect_ipv4(parts[0]) > 0.8 and detect_port(parts[1]) > 0.5:
            return 0.95
    return 0.0


def infer_single_value_type(val: str) -> Tuple[str, float]:
    """Evaluate a single value against all 14 field types and return (type_name, confidence)."""
    if not val:
        return "unknown", 0.0

    val_str = str(val).strip()

    # Check combined IP:port
    ip_port_conf = detect_ip_port(val_str)
    if ip_port_conf > 0.8:
        return "ip_port", ip_port_conf

    # Prioritized evaluations
    ipv4_conf = detect_ipv4(val_str)
    if ipv4_conf > 0.8:
        return "ipv4", ipv4_conf

    ipv6_conf = detect_ipv6(val_str)
    if ipv6_conf > 0.8:
        return "ipv6", ipv6_conf

    ts_conf = detect_timestamp(val_str)
    if ts_conf > 0.8:
        return "timestamp", ts_conf

    action_conf = detect_action(val_str)
    if action_conf > 0.8:
        return "action", action_conf

    url_conf = detect_url(val_str)
    if url_conf > 0.8:
        return "url", url_conf

    mac_conf = detect_mac(val_str)
    if mac_conf > 0.8:
        return "mac", mac_conf

    hash_conf = detect_hash(val_str)
    if hash_conf > 0.8:
        return "hash", hash_conf

    sev_conf = detect_severity(val_str)
    if sev_conf > 0.8:
        return "severity", sev_conf

    user_conf = detect_username(val_str)
    if user_conf > 0.8:
        return "username", user_conf

    fqdn_conf = detect_fqdn(val_str)
    if fqdn_conf > 0.8:
        return "fqdn", fqdn_conf

    port_conf = detect_port(val_str)
    if port_conf > 0.8:
        return "port", port_conf

    int_conf = detect_integer(val_str)
    if int_conf > 0.5:
        return "integer", int_conf

    host_conf = detect_hostname(val_str)
    if host_conf > 0.5:
        return "hostname", host_conf

    return "enum", 0.40
