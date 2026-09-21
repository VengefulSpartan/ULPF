import re
import json
import csv
import io
import xml.etree.ElementTree as ET
from typing import Union, List, Tuple
import structlog

from core.detector.models import DetectionResult

logger = structlog.get_logger()

# Regex Patterns
CEF_PATTERN = re.compile(
    r"^(?:<[0-9]{1,3}>)?(?:[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+)?CEF:\s*0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|(?P<signature>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|"
)

LEEF_PATTERN = re.compile(
    r"^(?:<[0-9]{1,3}>)?(?:[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+)?LEEF:\s*(?P<version>1\.0|2\.0)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dev_version>[^|]*)\|(?P<event_id>[^|]*)\|"
)

RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\[.*?\]|-)\s*"
)

RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)

KV_PAIR_PATTERN = re.compile(
    r'(?:^|\s+)(?P<key>[a-zA-Z0-9_.@-]+)=(?P<val>"[^"]*"|\'[^\']*\'|\S+)'
)


class FormatDetector:
    """Format detector classifying log lines into CEF, LEEF, JSON, XML, KV, CSV, RFC5424, RFC3164, or Unknown."""

    def detect(self, raw_data: Union[bytes, str]) -> DetectionResult:
        if isinstance(raw_data, bytes):
            try:
                text = raw_data.decode("utf-8", errors="replace").strip()
            except Exception:
                text = str(raw_data).strip()
        else:
            text = raw_data.strip()

        if not text:
            return DetectionResult(format="unknown", confidence=0.0, details={"reason": "empty input"})

        # 1. Test CEF
        cef_match = CEF_PATTERN.search(text)
        if cef_match:
            gd = cef_match.groupdict()
            return DetectionResult(
                format="cef",
                confidence=1.0,
                details=gd,
                fingerprint_rule="cef_header"
            )

        # 2. Test LEEF
        leef_match = LEEF_PATTERN.search(text)
        if leef_match:
            gd = leef_match.groupdict()
            return DetectionResult(
                format="leef",
                confidence=1.0,
                details=gd,
                fingerprint_rule="leef_header"
            )

        # 3. Test JSON
        if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, (dict, list)):
                    return DetectionResult(
                        format="json",
                        confidence=1.0,
                        details={"type": type(parsed).__name__, "keys": list(parsed.keys()) if isinstance(parsed, dict) else len(parsed)},
                        fingerprint_rule="json_parser"
                    )
            except Exception:
                pass

        # 4. Test XML
        if (text.startswith("<?xml") or text.startswith("<")) and text.endswith(">"):
            try:
                root = ET.fromstring(text)
                return DetectionResult(
                    format="xml",
                    confidence=1.0,
                    details={"root_tag": root.tag, "attrib": root.attrib},
                    fingerprint_rule="xml_parser"
                )
            except Exception:
                pass

        # 5. Test Syslog RFC5424
        rfc5424_match = RFC5424_PATTERN.match(text)
        if rfc5424_match:
            return DetectionResult(
                format="syslog_rfc5424",
                confidence=0.95,
                details=rfc5424_match.groupdict(),
                fingerprint_rule="syslog_rfc5424_header"
            )

        # 6. Test Syslog RFC3164
        rfc3164_match = RFC3164_PATTERN.match(text)
        if rfc3164_match:
            return DetectionResult(
                format="syslog_rfc3164",
                confidence=0.90,
                details=rfc3164_match.groupdict(),
                fingerprint_rule="syslog_rfc3164_header"
            )

        # 7. Test KV (Key-Value) format
        kv_matches = KV_PAIR_PATTERN.findall(text)
        if len(kv_matches) >= 3 and not (text.startswith("CEF:") or text.startswith("LEEF:")):
            keys = [m[0] for m in kv_matches]
            confidence = min(0.95, 0.70 + (len(kv_matches) * 0.05))
            return DetectionResult(
                format="kv",
                confidence=round(confidence, 2),
                details={"pair_count": len(kv_matches), "sample_keys": keys[:5]},
                fingerprint_rule="kv_pairs"
            )

        # 8. Test CSV format
        if "," in text and not (text.startswith("{") or text.startswith("<")):
            try:
                reader = csv.reader(io.StringIO(text))
                fields = next(reader, [])
                # Require >= 4 non-empty fields without key=value pairs or XML tags
                if len(fields) >= 4 and not any("=" in f for f in fields[:3]):
                    return DetectionResult(
                        format="csv",
                        confidence=0.80,
                        details={"field_count": len(fields)},
                        fingerprint_rule="csv_delimiter"
                    )
            except Exception:
                pass

        # 9. Fallback Unknown
        return DetectionResult(
            format="unknown",
            confidence=0.0,
            details={"raw_sample": text[:50]},
            fingerprint_rule="none"
        )
