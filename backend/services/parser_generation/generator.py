import re
import json
from typing import List, Dict, Any, Tuple, Optional
from backend.models.parser import ParserCandidate, ParserRule, FieldMapping, ParserValidationResult
from backend.services.parsing.detector import FormatDetector

class ParserGenerator:
    """
    USP 1: Zero-Touch Parser Generation Engine.
    Analyzes sample raw logs, infers format envelope, extracts structural tokens,
    generates candidate regex/KV rules, and maps extracted fields to OCSF schema.
    Works 100% offline via local heuristics and Drain-inspired tokenization.
    """

    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    PORT_PATTERN = re.compile(r'\b(?:port|spt|dpt|sport|dport)[:=]?\s*(\d{1,5})\b', re.IGNORECASE)
    ACTION_KEYWORDS = {
        "allow": ["allow", "permit", "accept", "pass"],
        "deny": ["deny", "denied", "block", "blocked", "reject", "drop", "dropped"],
        "alert": ["alert", "detected", "threat"]
    }
    SEV_KEYWORDS = ["info", "low", "medium", "warn", "warning", "high", "crit", "critical", "err", "error"]

    @classmethod
    def generate_candidate(
        cls,
        sample_logs: List[str],
        name: str,
        vendor: str,
        product: str,
        target_ocsf_class: int = 4001
    ) -> ParserCandidate:
        """
        Synthesizes a candidate parser from sample lines.
        Status is initialized as 'candidate', never approved silently.
        """
        if not sample_logs:
            raise ValueError("At least one sample log is required to generate a parser.")

        primary_sample = sample_logs[0].strip()
        detected_format, parsed = FormatDetector.detect_and_parse(primary_sample)

        mappings: List[FieldMapping] = []
        regex_pattern = None

        if detected_format in ["cef", "cef_syslog"]:
            fmt_type = "cef"
            mappings = [
                FieldMapping(source_field="src", target_field="src_endpoint.ip"),
                FieldMapping(source_field="spt", target_field="src_endpoint.port", transform="int"),
                FieldMapping(source_field="dst", target_field="dst_endpoint.ip"),
                FieldMapping(source_field="dpt", target_field="dst_endpoint.port", transform="int"),
                FieldMapping(source_field="proto", target_field="connection_info.protocol_name"),
                FieldMapping(source_field="act", target_field="disposition"),
                FieldMapping(source_field="severity_raw", target_field="severity_id", transform="int"),
            ]
        elif detected_format == "leef":
            fmt_type = "leef"
            mappings = [
                FieldMapping(source_field="src", target_field="src_endpoint.ip"),
                FieldMapping(source_field="dst", target_field="dst_endpoint.ip"),
                FieldMapping(source_field="usrName", target_field="user.name"),
                FieldMapping(source_field="proto", target_field="connection_info.protocol_name"),
            ]
        elif detected_format == "json":
            fmt_type = "json"
            # Map top-level keys if present
            if "src_ip" in parsed:
                mappings.append(FieldMapping(source_field="src_ip", target_field="src_endpoint.ip"))
            if "dest_ip" in parsed:
                mappings.append(FieldMapping(source_field="dest_ip", target_field="dst_endpoint.ip"))
            if "src_port" in parsed:
                mappings.append(FieldMapping(source_field="src_port", target_field="src_endpoint.port", transform="int"))
            if "dest_port" in parsed:
                mappings.append(FieldMapping(source_field="dest_port", target_field="dst_endpoint.port", transform="int"))
            if "proto" in parsed:
                mappings.append(FieldMapping(source_field="proto", target_field="connection_info.protocol_name"))
            if "event_type" in parsed:
                mappings.append(FieldMapping(source_field="event_type", target_field="activity_name"))
        elif detected_format in ["kv", "syslog_kv"]:
            fmt_type = "kv"
            # Check for standard KV keys
            for k in parsed.keys():
                k_lower = k.lower()
                if k_lower in ["src", "srcip", "source_ip", "saddr"]:
                    mappings.append(FieldMapping(source_field=k, target_field="src_endpoint.ip"))
                elif k_lower in ["dst", "dstip", "destination_ip", "daddr"]:
                    mappings.append(FieldMapping(source_field=k, target_field="dst_endpoint.ip"))
                elif k_lower in ["spt", "srcport", "sport"]:
                    mappings.append(FieldMapping(source_field=k, target_field="src_endpoint.port", transform="int"))
                elif k_lower in ["dpt", "dstport", "dport"]:
                    mappings.append(FieldMapping(source_field=k, target_field="dst_endpoint.port", transform="int"))
                elif k_lower in ["proto", "protocol"]:
                    mappings.append(FieldMapping(source_field=k, target_field="connection_info.protocol_name"))
                elif k_lower in ["act", "action", "status"]:
                    mappings.append(FieldMapping(source_field=k, target_field="disposition"))
                elif k_lower in ["user", "username", "suser"]:
                    mappings.append(FieldMapping(source_field=k, target_field="user.name"))
        else:
            # Unstructured syslog / text: infer regex template
            fmt_type = "regex"
            # Extract IPs
            ips = cls.IP_PATTERN.findall(primary_sample)
            if len(ips) >= 2:
                regex_pattern = r'(?P<src_ip>\b(?:\d{1,3}\.){3}\d{1,3}\b).*?(?P<dst_ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)'
                mappings = [
                    FieldMapping(source_field="src_ip", target_field="src_endpoint.ip"),
                    FieldMapping(source_field="dst_ip", target_field="dst_endpoint.ip"),
                ]
            else:
                regex_pattern = r'(?P<message>.*)'
                mappings = [FieldMapping(source_field="message", target_field="unmapped.message")]

        rule = ParserRule(
            format_type=fmt_type,
            regex_pattern=regex_pattern,
            mappings=mappings
        )

        candidate = ParserCandidate(
            name=name,
            vendor=vendor,
            product=product,
            format_type=fmt_type,
            description=f"Auto-generated candidate parser for {vendor} {product} ({fmt_type.upper()})",
            target_ocsf_class=target_ocsf_class,
            rule=rule,
            status="candidate",
            tested=False
        )

        return candidate
