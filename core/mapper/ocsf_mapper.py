import yaml
from typing import List, Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class OCSFMapper:
    """Maps inferred slot types and token context to standardized OCSF fields."""

    def map_slots_to_ocsf(
        self,
        template_mined: str,
        slot_profiles: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Map profiled slots to OCSF standard schema fields.
        
        Args:
            template_mined: The mined log template string containing <*>
            slot_profiles: Output from VariableProfiler.profile_variable_positions()
            
        Returns:
            List of field mapping dictionaries.
        """
        mappings = []
        
        ip_count = 0
        port_count = 0

        # Break template around <*> slots to inspect preceding token hints
        parts = template_mined.split("<*>")

        for profile in slot_profiles:
            slot_idx = profile["slot_index"]
            inferred_type = profile["inferred_type"]
            base_conf = profile["confidence"]
            
            # Extract preceding text token context
            preceding_text = parts[slot_idx].lower() if slot_idx < len(parts) else ""
            
            ocsf_field = None
            mapping_conf = base_conf

            if inferred_type == "ip_port":
                ip_count += 1
                port_count += 1
                if "src" in preceding_text or "from" in preceding_text or ip_count == 1:
                    mappings.append({
                        "slot_index": slot_idx,
                        "inferred_type": "ip_port",
                        "ocsf_field": "src_endpoint.ip",
                        "confidence": round(min(1.0, base_conf + 0.05), 2),
                        "sample_values": profile.get("sample_values", [])
                    })
                    mappings.append({
                        "slot_index": slot_idx,
                        "inferred_type": "ip_port",
                        "ocsf_field": "src_endpoint.port",
                        "confidence": round(min(1.0, base_conf + 0.05), 2),
                        "sample_values": profile.get("sample_values", [])
                    })
                else:
                    mappings.append({
                        "slot_index": slot_idx,
                        "inferred_type": "ip_port",
                        "ocsf_field": "dst_endpoint.ip",
                        "confidence": round(min(1.0, base_conf + 0.05), 2),
                        "sample_values": profile.get("sample_values", [])
                    })
                    mappings.append({
                        "slot_index": slot_idx,
                        "inferred_type": "ip_port",
                        "ocsf_field": "dst_endpoint.port",
                        "confidence": round(min(1.0, base_conf + 0.05), 2),
                        "sample_values": profile.get("sample_values", [])
                    })
                continue

            if inferred_type in ("ipv4", "ipv6"):
                ip_count += 1
                if "src" in preceding_text or "source" in preceding_text or ip_count == 1:
                    ocsf_field = "src_endpoint.ip"
                    mapping_conf = min(1.0, base_conf + 0.10)
                elif "dst" in preceding_text or "dest" in preceding_text or "destination" in preceding_text or ip_count == 2:
                    ocsf_field = "dst_endpoint.ip"
                    mapping_conf = min(1.0, base_conf + 0.10)
                else:
                    ocsf_field = f"endpoint_{ip_count}.ip"

            elif inferred_type == "port":
                port_count += 1
                if "src" in preceding_text or "sport" in preceding_text or "spt" in preceding_text or port_count == 1:
                    ocsf_field = "src_endpoint.port"
                    mapping_conf = min(1.0, base_conf + 0.15)
                elif "dst" in preceding_text or "dport" in preceding_text or "dpt" in preceding_text or port_count == 2:
                    ocsf_field = "dst_endpoint.port"
                    mapping_conf = min(1.0, base_conf + 0.15)
                else:
                    ocsf_field = f"endpoint_{port_count}.port"

            elif inferred_type == "timestamp":
                ocsf_field = "time"
                mapping_conf = max(base_conf, 0.95)

            elif inferred_type == "action":
                ocsf_field = "disposition"
                mapping_conf = max(base_conf, 0.90)

            elif inferred_type == "severity":
                ocsf_field = "severity"
                mapping_conf = max(base_conf, 0.90)

            elif inferred_type == "username":
                ocsf_field = "user.name"
                mapping_conf = max(base_conf, 0.85)

            elif inferred_type == "hostname":
                ocsf_field = "device.hostname"
                mapping_conf = max(base_conf, 0.75)

            if ocsf_field:
                mapping_record = {
                    "slot_index": slot_idx,
                    "inferred_type": inferred_type,
                    "ocsf_field": ocsf_field,
                    "confidence": round(mapping_conf, 2),
                    "sample_values": profile.get("sample_values", [])
                }
                mappings.append(mapping_record)
                logger.info(
                    "ocsf_mapping_created",
                    slot_index=slot_idx,
                    inferred_type=inferred_type,
                    ocsf_field=ocsf_field,
                    confidence=mapping_conf
                )

        return mappings

    def generate_draft_plugin(
        self,
        parser_id: str,
        template_mined: str,
        field_mappings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate a draft parser plugin metadata dictionary."""
        return {
            "parser_id": parser_id,
            "version": "1.0.0-draft",
            "status": "draft_suggested",
            "template_mined": template_mined,
            "field_mappings": field_mappings
        }

    def emit_plugin_yaml(self, plugin_dict: Dict[str, Any]) -> str:
        """Serialize plugin mapping definition to YAML format."""
        return yaml.dump(plugin_dict, sort_keys=False, default_flow_style=False)
