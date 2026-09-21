from typing import Dict, Any, List, Set
import structlog

logger = structlog.get_logger()


class EntityExtractor:
    """Extracts security entities (IP, User, Host, Process, Session) from normalized OCSF events."""

    def extract_entities(self, event: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract typed entities from an OCSF JSON event dict."""
        entities: Dict[str, Set[str]] = {
            "ip": set(),
            "user": set(),
            "host": set(),
            "process": set(),
            "session": set()
        }

        # IP Entities
        if "src_endpoint" in event and isinstance(event["src_endpoint"], dict):
            if "ip" in event["src_endpoint"]:
                entities["ip"].add(str(event["src_endpoint"]["ip"]))
            if "hostname" in event["src_endpoint"]:
                entities["host"].add(str(event["src_endpoint"]["hostname"]))

        if "dst_endpoint" in event and isinstance(event["dst_endpoint"], dict):
            if "ip" in event["dst_endpoint"]:
                entities["ip"].add(str(event["dst_endpoint"]["ip"]))
            if "hostname" in event["dst_endpoint"]:
                entities["host"].add(str(event["dst_endpoint"]["hostname"]))

        if "client_ip" in event:
            entities["ip"].add(str(event["client_ip"]))

        # User Entities
        if "user" in event and isinstance(event["user"], dict):
            if "name" in event["user"]:
                entities["user"].add(str(event["user"]["name"]))

        if "actor" in event and isinstance(event["actor"], dict):
            actor_user = event["actor"].get("user", {})
            if isinstance(actor_user, dict) and "name" in actor_user:
                entities["user"].add(str(actor_user["name"]))

        if "target_user" in event:
            entities["user"].add(str(event["target_user"]))

        # Host Entities
        if "device" in event and isinstance(event["device"], dict):
            if "hostname" in event["device"]:
                entities["host"].add(str(event["device"]["hostname"]))

        # Process Entities
        if "process" in event and isinstance(event["process"], dict):
            proc_name = event["process"].get("name") or event["process"].get("file", {}).get("name")
            if proc_name:
                entities["process"].add(str(proc_name))

        # Session Entities
        if "session" in event and isinstance(event["session"], dict):
            session_id = event["session"].get("uid") or event["session"].get("id")
            if session_id:
                entities["session"].add(str(session_id))

        return entities
