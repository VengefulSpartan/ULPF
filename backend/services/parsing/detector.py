import re
from typing import Tuple, Dict, Any
from backend.services.parsing.cef_parser import CEFParser
from backend.services.parsing.leef_parser import LEEFParser
from backend.services.parsing.json_parser import JSONParser
from backend.services.parsing.syslog_parser import SyslogParser
from backend.services.parsing.kv_parser import KVParser

class FormatDetector:
    """
    Intelligently identifies the format of incoming network log lines.
    """
    @classmethod
    def detect_and_parse(cls, raw_line: str) -> Tuple[str, Dict[str, Any]]:
        line = raw_line.strip()
        if not line:
            return "empty", {}

        # 1. JSON
        if line.startswith("{") and line.endswith("}"):
            success, data = JSONParser.parse(line)
            if success:
                return "json", data

        # 2. CEF
        if "CEF:" in line:
            success, data = CEFParser.parse(line)
            if success:
                return "cef", data

        # 3. LEEF
        if "LEEF:" in line:
            success, data = LEEFParser.parse(line)
            if success:
                return "leef", data

        # 4. Syslog (RFC 5424 or 3164)
        if line.startswith("<"):
            success, data = SyslogParser.parse(line)
            if success:
                msg = data.get("message", "")
                # Check if message itself is KV or CEF
                if "CEF:" in msg:
                    c_ok, c_data = CEFParser.parse(msg)
                    if c_ok:
                        c_data["syslog_envelope"] = data
                        return "cef_syslog", c_data
                if msg:
                    kv_ok, kv_data = KVParser.parse(msg)
                    if kv_ok:
                        data.update(kv_data)
                        return "syslog_kv", data
                return "syslog", data

        # 5. Key-Value
        success, data = KVParser.parse(line)
        if success:
            return "kv", data

        # 6. Unstructured text
        return "unstructured", {"raw_text": line, "_format": "unstructured"}
