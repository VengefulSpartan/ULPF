import re
from typing import Dict, Any, Tuple

class KVParser:
    """
    Parses key-value formatted logs: key=value key="value with spaces"
    Common in FortiGate, Check Point, Palo Alto, Cisco ASA syslog bodies.
    """
    # Pattern to capture key=val where val can be "double quoted", 'single quoted', or unquoted
    KV_PATTERN = re.compile(r'([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,;]+))')

    @classmethod
    def parse(cls, line: str) -> Tuple[bool, Dict[str, Any]]:
        matches = cls.KV_PATTERN.findall(line)
        if not matches or len(matches) < 2:
            return False, {}

        fields: Dict[str, Any] = {"_format": "kv"}
        for k, v_double, v_single, v_raw in matches:
            val = v_double or v_single or v_raw or ""
            fields[k] = val

        return True, fields
