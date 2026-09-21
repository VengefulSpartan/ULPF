import re
from typing import Dict, Any, Tuple

class LEEFParser:
    """
    Parses Log Event Extended Format (LEEF) strings (v1.0 and v2.0).
    Format: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter]|Extension
    """
    @classmethod
    def parse(cls, line: str) -> Tuple[bool, Dict[str, Any]]:
        leef_idx = line.find("LEEF:")
        if leef_idx != -1:
            line = line[leef_idx:]
        else:
            return False, {}

        parts = line.split("|")
        if len(parts) < 6:
            return False, {}

        version_part = parts[0].replace("LEEF:", "").strip()
        vendor = parts[1].strip()
        product = parts[2].strip()
        dev_version = parts[3].strip()
        event_id = parts[4].strip()

        # Check delimiter parameter in LEEF 2.0
        delimiter = "\t" # default
        extension_str = ""
        if len(parts) == 6:
            extension_str = parts[5]
        elif len(parts) >= 7:
            # If 7 parts, parts[5] is custom delimiter or part of extension
            if len(parts[5]) == 1 or parts[5].startswith("x") or parts[5].startswith("0x"):
                delimiter = parts[5]
                extension_str = "|".join(parts[6:])
            else:
                extension_str = "|".join(parts[5:])

        data: Dict[str, Any] = {
            "_format": "leef",
            "leef_version": version_part,
            "vendor": vendor,
            "product": product,
            "device_version": dev_version,
            "event_id": event_id,
        }

        # Parse key-value pairs
        # Often tab-delimited or key=value separated by delimiter
        pairs = []
        if delimiter in extension_str:
            pairs = extension_str.split(delimiter)
        else:
            # Fallback to whitespace or key=value regex
            pattern = re.compile(r'([a-zA-Z0-9_.-]+)=')
            matches = list(pattern.finditer(extension_str))
            for i, match in enumerate(matches):
                key = match.group(1)
                start_val = match.end()
                end_val = matches[i + 1].start() if i + 1 < len(matches) else len(extension_str)
                val = extension_str[start_val:end_val].strip()
                pairs.append(f"{key}={val}")

        for pair in pairs:
            if "=" in pair:
                k, v = pair.split("=", 1)
                data[k.strip()] = v.strip().strip('"')

        return True, data
