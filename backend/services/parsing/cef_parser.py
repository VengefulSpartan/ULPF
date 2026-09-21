import re
from typing import Dict, Any, Tuple

class CEFParser:
    """
    Parses ArcSight Common Event Format (CEF) strings.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    HEADER_REGEX = re.compile(
        r'CEF:\s*(\d+)\s*\|([^|\\]*(?:\\.[^|\\]*)*)\|([^|\\]*(?:\\.[^|\\]*)*)\|'
        r'([^|\\]*(?:\\.[^|\\]*)*)\|([^|\\]*(?:\\.[^|\\]*)*)\|([^|\\]*(?:\\.[^|\\]*)*)\|'
        r'([^|\\]*(?:\\.[^|\\]*)*)\|(.*)'
    )

    @classmethod
    def parse_extension(cls, ext_str: str) -> Dict[str, Any]:
        """
        Parses CEF extension key=value pairs, respecting quoted strings and whitespace.
        """
        fields: Dict[str, Any] = {}
        if not ext_str:
            return fields

        # Pattern matches key=value where value runs until the next key= or end of string
        # A key is typically alphanumeric string followed by '='
        pattern = re.compile(r'([a-zA-Z0-9_.-]+)=')
        matches = list(pattern.finditer(ext_str))
        
        for i, match in enumerate(matches):
            key = match.group(1)
            start_val = match.end()
            if i + 1 < len(matches):
                end_val = matches[i + 1].start()
                val = ext_str[start_val:end_val].strip()
            else:
                val = ext_str[start_val:].strip()
            
            # Strip outer quotes if any
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            fields[key] = val

        return fields

    @classmethod
    def parse(cls, line: str) -> Tuple[bool, Dict[str, Any]]:
        # Remove any leading syslog prefix if CEF is embedded inside syslog
        cef_idx = line.find("CEF:")
        if cef_idx != -1:
            line = line[cef_idx:]
        else:
            return False, {}

        match = cls.HEADER_REGEX.match(line)
        if not match:
            return False, {}

        version = match.group(1)
        vendor = match.group(2)
        product = match.group(3)
        dev_version = match.group(4)
        class_id = match.group(5)
        name = match.group(6)
        severity = match.group(7)
        extension_str = match.group(8)

        data: Dict[str, Any] = {
            "_format": "cef",
            "cef_version": version,
            "vendor": vendor,
            "product": product,
            "device_version": dev_version,
            "event_class_id": class_id,
            "event_name": name,
            "severity_raw": severity,
        }

        # Parse extension
        ext_fields = cls.parse_extension(extension_str)
        data.update(ext_fields)
        return True, data
