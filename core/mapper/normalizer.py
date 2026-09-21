import os
import json
import jsonschema
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import structlog

from ingest.models import RawEvent
from core.plugins.registry import PluginRegistry, ParserPlugin

logger = structlog.get_logger()

SCHEMA_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "schema", "ocsf_schema.json")
)


class OCSFNormalizer:
    """Transforms raw events into normalized OCSF JSON events with byte-traceable raw_ref."""

    def __init__(self, registry: Optional[PluginRegistry] = None):
        self.registry = registry or PluginRegistry()
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def normalize(
        self,
        raw_event: RawEvent,
        extracted_variables: Optional[list] = None,
        plugin: Optional[ParserPlugin] = None
    ) -> Dict[str, Any]:
        """Normalize RawEvent into OCSF JSON schema."""

        # 1. Determine timestamp
        try:
            dt = datetime.fromisoformat(raw_event.receipt_ts)
            epoch_ts = int(dt.timestamp())
        except Exception:
            epoch_ts = int(datetime.now(timezone.utc).timestamp())

        archive_path = raw_event.source_metadata.get("archive_path", f"raw/{raw_event.uuid}")

        # Base OCSF event payload
        ocsf_event: Dict[str, Any] = {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "severity_id": 1,
            "activity_id": 1,
            "activity_name": "Traffic Log",
            "time": epoch_ts,
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "vendor_name": "ULPF",
                    "name": "ULPF Engine"
                }
            },
            "raw_ref": {
                "uuid": raw_event.uuid,
                "sha256": raw_event.sha256,
                "archive_path": archive_path
            },
            "parser_id": plugin.parser_id if plugin else "draft_auto_parser",
            "parser_version": plugin.version if plugin else "1.0.0-draft"
        }

        # Apply plugin mappings if variables provided
        if plugin and extracted_variables:
            src_endpoint = {}
            dst_endpoint = {}

            for mapping in plugin.field_mappings:
                slot_idx = mapping.get("slot_index", -1)
                ocsf_field = mapping.get("ocsf_field")
                
                if 0 <= slot_idx < len(extracted_variables):
                    val = extracted_variables[slot_idx]
                    
                    if ":" in str(val) and mapping.get("inferred_type") == "ip_port":
                        parts = str(val).split(":")
                        ip_val = parts[0]
                        port_val = int(parts[1]) if parts[1].isdigit() else 0
                        
                        if "src_endpoint" in ocsf_field:
                            src_endpoint["ip"] = ip_val
                            src_endpoint["port"] = port_val
                        elif "dst_endpoint" in ocsf_field:
                            dst_endpoint["ip"] = ip_val
                            dst_endpoint["port"] = port_val
                    else:
                        if ocsf_field == "src_endpoint.ip":
                            src_endpoint["ip"] = str(val)
                        elif ocsf_field == "src_endpoint.port" and str(val).isdigit():
                            src_endpoint["port"] = int(val)
                        elif ocsf_field == "dst_endpoint.ip":
                            dst_endpoint["ip"] = str(val)
                        elif ocsf_field == "dst_endpoint.port" and str(val).isdigit():
                            dst_endpoint["port"] = int(val)
                        elif ocsf_field == "disposition":
                            ocsf_event["disposition"] = str(val)
                        elif ocsf_field == "user.name":
                            ocsf_event["user"] = {"name": str(val)}

            if src_endpoint:
                ocsf_event["src_endpoint"] = src_endpoint
            if dst_endpoint:
                ocsf_event["dst_endpoint"] = dst_endpoint

        # Validate against local OCSF schema
        jsonschema.validate(instance=ocsf_event, schema=self.schema)
        return ocsf_event
