import re
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from backend.models.event import (
    OCSFEvent, Metadata, ProductMetadata, RawRef,
    Endpoint, ConnectionInfo, Traffic, User, Finding
)

class OCSFNormalizer:
    """
    Normalizes parsed log dictionaries into OCSF v1.1.0 compatible schema.
    Explicitly targets (class_uid = category_uid * 1000 + class id):
    - Class 4001: Network Activity   (activity 6 = Traffic, 1 = Open, 2 = Close, 5 = Refuse)
    - Class 3002: Authentication     (activity 1 = Logon, 2 = Logoff)
    - Class 2004: Detection Finding  (activity 1 = Create); replaces Security Finding
      (2001), which OCSF deprecated in 1.1.0.
    - Class 0:    Base Event         (activity 99 = Other) for lines that carry no
      network, identity or detection semantics (system messages, unparseable text),
      so they are never mislabelled as Network Activity.

    Vendor packs may pass hints in the parsed dict: ``_ocsf_class``,
    ``_activity_id`` and ``_activity_name`` override the heuristics below.
    """

    CLASS_INFO = {
        4001: ("Network Activity", 4, "Network Activity", 6, "Traffic"),
        3002: ("Authentication", 3, "Identity & Access Management", 1, "Logon"),
        2004: ("Detection Finding", 2, "Findings", 1, "Create"),
        0: ("Base Event", 0, "Uncategorized", 99, "Other"),
    }

    # Field aliases
    SRC_IP_ALIASES = ["src", "src_ip", "srcip", "source_ip", "saddr", "c-ip", "sourceAddress", "src_addr", "client_ip"]
    SRC_PORT_ALIASES = ["spt", "src_port", "srcport", "sourcePort", "sport", "source_port", "client_port"]
    DST_IP_ALIASES = ["dst", "dst_ip", "dstip", "destination_ip", "daddr", "cs-ip", "destinationAddress", "dst_addr", "server_ip"]
    DST_PORT_ALIASES = ["dpt", "dst_port", "dstport", "destinationPort", "dport", "destination_port", "server_port"]
    PROTO_ALIASES = ["proto", "protocol", "transport", "protocol_name", "app", "proto_name"]
    ACTION_ALIASES = ["act", "action", "disposition", "status", "result", "outcome", "decision"]
    USER_ALIASES = ["user", "username", "suser", "duser", "src_user", "dst_user", "usrName", "account"]
    BYTES_IN_ALIASES = ["bytes_in", "in_bytes", "rcvdbyte", "bytesIn", "inBytes", "bytes_received"]
    BYTES_OUT_ALIASES = ["bytes_out", "out_bytes", "sentbyte", "bytesOut", "outBytes", "bytes_sent"]

    @classmethod
    def find_first(cls, data: Dict[str, Any], aliases: list) -> Optional[Any]:
        for alias in aliases:
            # Check exact match
            if alias in data and data[alias] is not None:
                return data[alias]
            # Check case-insensitive
            for k, v in data.items():
                if k.lower() == alias.lower() and v is not None:
                    return v
        return None

    @classmethod
    def normalize_severity(cls, raw_sev: Any) -> Tuple[int, str]:
        """
        Normalizes severity to OCSF 1-5 scale:
        1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical
        """
        if raw_sev is None:
            return 1, "Informational"

        s = str(raw_sev).strip().lower()
        # Numeric check
        try:
            val = float(s)
            if val >= 8 or val >= 4.5:
                return 5, "Critical"
            elif val >= 6 or val >= 3.5:
                return 4, "High"
            elif val >= 4 or val >= 2.5:
                return 3, "Medium"
            elif val >= 2 or val >= 1.5:
                return 2, "Low"
            else:
                return 1, "Informational"
        except ValueError:
            pass

        # Textual check
        if any(x in s for x in ["crit", "emerg", "alert", "fatal"]):
            return 5, "Critical"
        if any(x in s for x in ["err", "high", "severe"]):
            return 4, "High"
        if any(x in s for x in ["warn", "med", "notice"]):
            return 3, "Medium"
        if any(x in s for x in ["low", "debug"]):
            return 2, "Low"
        return 1, "Informational"

    @classmethod
    def normalize_action(cls, raw_act: Any) -> Tuple[Optional[str], Optional[str]]:
        """Returns (disposition, action)"""
        if not raw_act:
            return None, None
        a = str(raw_act).strip().lower()
        if any(x in a for x in ["allow", "accept", "pass", "permit", "success"]):
            return "allowed", "allow"
        if any(x in a for x in ["deny", "denied", "block", "blocked", "reject"]):
            return "denied", "deny"
        if any(x in a for x in ["drop", "dropped", "discard"]):
            return "dropped", "drop"
        if any(x in a for x in ["alert", "detect", "warn"]):
            return "alert", "alert"
        return a, a

    @classmethod
    def parse_timestamp(cls, raw_ts: Any) -> Tuple[str, int]:
        """Returns (ISO 8601 string, epoch milliseconds)"""
        now = datetime.now(timezone.utc)
        if not raw_ts:
            return now.isoformat(), int(now.timestamp() * 1000)

        # Epoch seconds or milliseconds
        try:
            val = float(raw_ts)
            if val > 1e11: # milliseconds
                dt = datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
            else:
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.isoformat(), int(dt.timestamp() * 1000)
        except (ValueError, TypeError, OSError):
            pass

        # ISO string parsing
        s = str(raw_ts).strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    # If format doesn't have year (like BSD syslog '%b %d %H:%M:%S')
                    if dt.year == 1900:
                        dt = dt.replace(year=now.year)
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat(), int(dt.timestamp() * 1000)
            except ValueError:
                continue

        return now.isoformat(), int(now.timestamp() * 1000)

    @classmethod
    def normalize(
        cls,
        parsed_data: Dict[str, Any],
        raw_text: str,
        raw_id: str,
        raw_hash: str,
        vendor: str = "Generic",
        product: str = "Network Device",
        sequence_num: int = 1
    ) -> OCSFEvent:
        data = dict(parsed_data)
        unmapped = {}

        # 1. Determine Class UID
        # Check if Detection Finding (alert, signature, attack)
        finding_title = cls.find_first(data, ["signature", "rule_name", "attack", "threat_name", "alert", "event_name", "msg"])
        is_finding = bool(cls.find_first(data, ["alert", "signature", "threat_name", "attack", "ids_type"])) or "IDS" in product.upper() or "SURICATA" in product.upper() or "SNORT" in product.upper()
        
        # Check if Authentication
        user_val = cls.find_first(data, cls.USER_ALIASES)
        is_auth = bool(user_val and any(x in str(raw_text).lower() for x in ["login", "logon", "auth", "vpn", "session-open"])) or "VPN" in product.upper()

        hinted_class = data.get("_ocsf_class")
        if hinted_class in cls.CLASS_INFO:
            class_uid = hinted_class
            is_finding = class_uid == 2004
            is_auth = class_uid == 3002
        elif is_finding:
            class_uid = 2004
        elif is_auth:
            class_uid = 3002
        elif cls.find_first(data, cls.SRC_IP_ALIASES) or cls.find_first(data, cls.DST_IP_ALIASES):
            class_uid = 4001
        else:
            class_uid = 0
        class_name, category_uid, category_name, activity_id, activity_name = cls.CLASS_INFO[class_uid]
        if isinstance(data.get("_activity_id"), int):
            activity_id = data["_activity_id"]
            activity_name = str(data.get("_activity_name") or activity_name)

        # 2. Extract Endpoints
        src_ip = cls.find_first(data, cls.SRC_IP_ALIASES)
        src_port_raw = cls.find_first(data, cls.SRC_PORT_ALIASES)
        src_port = None
        if src_port_raw is not None:
            try:
                src_port = int(src_port_raw)
            except (ValueError, TypeError):
                pass

        src_endpoint = Endpoint(ip=str(src_ip) if src_ip else None, port=src_port)

        dst_ip = cls.find_first(data, cls.DST_IP_ALIASES)
        dst_port_raw = cls.find_first(data, cls.DST_PORT_ALIASES)
        dst_port = None
        if dst_port_raw is not None:
            try:
                dst_port = int(dst_port_raw)
            except (ValueError, TypeError):
                pass

        dst_endpoint = Endpoint(ip=str(dst_ip) if dst_ip else None, port=dst_port)

        # 3. Connection & Traffic
        proto = cls.find_first(data, cls.PROTO_ALIASES)
        connection_info = ConnectionInfo(protocol_name=str(proto).upper() if proto else None)

        bytes_in_raw = cls.find_first(data, cls.BYTES_IN_ALIASES)
        bytes_out_raw = cls.find_first(data, cls.BYTES_OUT_ALIASES)
        traffic = None
        if bytes_in_raw is not None or bytes_out_raw is not None:
            try:
                b_in = int(bytes_in_raw) if bytes_in_raw is not None else None
                b_out = int(bytes_out_raw) if bytes_out_raw is not None else None
                traffic = Traffic(bytes_in=b_in, bytes_out=b_out)
            except (ValueError, TypeError):
                pass

        # 4. Action / Disposition / Status
        action_val = cls.find_first(data, cls.ACTION_ALIASES)
        disposition, action = cls.normalize_action(action_val)
        
        status_val = None
        if is_auth:
            if disposition == "allowed" or (action_val and "success" in str(action_val).lower()):
                status_val = "success"
            elif disposition in ["denied", "dropped"] or (action_val and "fail" in str(action_val).lower()):
                status_val = "failure"

        # 5. Severity
        raw_sev = cls.find_first(data, ["severity_raw", "severity", "level", "priority", "severity_code"])
        severity_id, severity = cls.normalize_severity(raw_sev)

        # 6. Timestamp
        raw_ts = cls.find_first(data, ["timestamp", "time", "date", "rt", "deviceReceiptTime", "start"])
        iso_time, epoch_ms = cls.parse_timestamp(raw_ts)

        # 7. User & Finding
        user_obj = User(name=str(user_val)) if user_val else None
        
        finding_obj = None
        if is_finding and finding_title:
            finding_obj = Finding(
                title=str(finding_title),
                desc=str(data.get("desc", finding_title)),
                uid=str(data.get("event_class_id", data.get("rule_id", "SIG-UNKNOWN")))
            )

        # 8. Unmapped fields gathering
        mapped_keys = {
            "src", "src_ip", "srcip", "source_ip", "saddr", "c-ip", "sourceAddress", "src_addr", "client_ip",
            "spt", "src_port", "srcport", "sourcePort", "sport", "source_port", "client_port",
            "dst", "dst_ip", "dstip", "destination_ip", "daddr", "cs-ip", "destinationAddress", "dst_addr", "server_ip",
            "dpt", "dst_port", "dstport", "destinationPort", "dport", "destination_port", "server_port",
            "proto", "protocol", "transport", "protocol_name", "app", "proto_name",
            "act", "action", "disposition", "status", "result", "outcome", "decision",
            "user", "username", "suser", "duser", "src_user", "dst_user", "usrName", "account",
            "bytes_in", "in_bytes", "rcvdbyte", "bytesIn", "inBytes", "bytes_received",
            "bytes_out", "out_bytes", "sentbyte", "bytesOut", "outBytes", "bytes_sent",
            "timestamp", "time", "date", "rt", "deviceReceiptTime", "start",
            "severity_raw", "severity", "level", "priority", "severity_code",
            "_format"
        }
        for k, v in data.items():
            if k not in mapped_keys and not k.startswith("_"):
                unmapped[k] = v
        if data.get("_pack"):
            unmapped["parser_pack"] = data["_pack"]

        # Metadata
        metadata = Metadata(
            version="1.1.0",
            product=ProductMetadata(
                vendor_name=str(data.get("vendor", vendor)),
                name=str(data.get("product", product)),
                version=data.get("device_version")
            ),
            sequence_num=sequence_num,
            raw_ref=RawRef(raw_id=raw_id, raw_hash=raw_hash)
        )

        return OCSFEvent(
            class_uid=class_uid,
            type_uid=class_uid * 100 + activity_id,
            class_name=class_name,
            category_uid=category_uid,
            category_name=category_name,
            activity_id=activity_id,
            activity_name=activity_name,
            severity_id=severity_id,
            severity=severity,
            time=iso_time,
            time_epoch_ms=epoch_ms,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            connection_info=connection_info,
            traffic=traffic,
            disposition=disposition,
            action=action,
            user=user_obj,
            status=status_val,
            finding=finding_obj,
            metadata=metadata,
            raw_data=raw_text,
            unmapped=unmapped
        )
