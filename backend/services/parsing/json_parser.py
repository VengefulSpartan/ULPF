import json
from typing import Dict, Any, Tuple

class JSONParser:
    """
    Parses single-line JSON log objects (e.g. Suricata EVE, AWS VPC flow logs, cloud firewalls).
    """
    @classmethod
    def parse(cls, line: str) -> Tuple[bool, Dict[str, Any]]:
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            return False, {}

        try:
            data = json.loads(line)
            if isinstance(data, dict):
                data["_format"] = "json"
                return True, data
            return False, {}
        except Exception:
            return False, {}
