"""Single entry point for turning a raw log line into parsed fields."""
from typing import Any, Dict, Tuple

from backend.services.parsing.detector import FormatDetector
from backend.services.vendors import parse_vendor


def parse_log(raw_text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Try the vendor packs first (native formats of major perimeter devices),
    then the generic CEF / LEEF / syslog / key=value / JSON parsers.
    Returns (format_detected, parsed_fields).
    """
    hit = parse_vendor(raw_text)
    if hit:
        return hit
    return FormatDetector.detect_and_parse(raw_text)
