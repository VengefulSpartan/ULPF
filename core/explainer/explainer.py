import os
import yaml
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger()

VALID_INTENTS = {
    "reconnaissance",
    "policy_violation",
    "credential_attack",
    "exfiltration_attempt",
    "operational_noise"
}

DEFAULT_RULES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "rules.yaml")
)


class SemanticExplainer:
    """Semantic Annotation Engine ("Log Explained").
    Converts normalized OCSF events into one-sentence human-readable explanations
    and intent tags using a configurable YAML rule table with robust non-crashing fallbacks.
    """

    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load rule table from YAML file."""
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "rules" in data:
                        self.rules = data["rules"]
                    elif isinstance(data, list):
                        self.rules = data
                logger.info("explainer_rules_loaded", count=len(self.rules), path=self.rules_path)
            except Exception as exc:
                logger.error("explainer_rules_load_failed", error=str(exc))
                self.rules = []
        else:
            logger.warning("explainer_rules_file_not_found", path=self.rules_path)
            self.rules = []

    def explain_event(self, event: Dict[str, Any]) -> Dict[str, str]:
        """Produce a human-readable explanation and intent tag for an OCSF event.
        
        Returns:
            Dict containing 'explanation' (str) and 'intent' (str).
            Guaranteed to never return empty string or crash.
        """
        if not isinstance(event, dict):
            return {
                "explanation": "Unrecognized raw event payload.",
                "intent": "operational_noise"
            }

        class_uid = event.get("class_uid")
        activity_id = event.get("activity_id")
        disposition = str(event.get("disposition", "UNKNOWN")).upper()

        # Extract placeholder parameters safely
        src_ip = (
            event.get("src_endpoint", {}).get("ip") or
            event.get("client", {}).get("ip") or
            "unknown_src"
        )
        src_port = event.get("src_endpoint", {}).get("port") or "any"

        dst_ip = (
            event.get("dst_endpoint", {}).get("ip") or
            event.get("server", {}).get("ip") or
            "unknown_dst"
        )
        dst_port = event.get("dst_endpoint", {}).get("port") or "any"

        user_name = (
            event.get("user", {}).get("name") or
            event.get("actor", {}).get("user", {}).get("name") or
            "unknown_user"
        )

        process_name = event.get("process", {}).get("name") or "unknown_process"
        device_hostname = event.get("device", {}).get("hostname") or "unknown_host"
        url = event.get("url", {}).get("url") or "unknown_url"

        params = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "user_name": user_name,
            "process_name": process_name,
            "device_hostname": device_hostname,
            "url": url,
            "class_name": event.get("class_name", "Security Activity"),
            "activity_name": event.get("activity_name", "Event"),
            "disposition": disposition
        }

        # 1. Exact Rule Match (class_uid, activity_id, disposition)
        matched_rule = None
        for rule in self.rules:
            r_class = rule.get("class_uid")
            r_act = rule.get("activity_id")
            r_disp = str(rule.get("disposition", "")).upper()

            if r_class == class_uid and r_act == activity_id:
                if not r_disp or r_disp == disposition:
                    matched_rule = rule
                    break

        if matched_rule:
            template = matched_rule.get("template", "")
            intent = matched_rule.get("intent", "operational_noise")
            try:
                explanation = template.format(**params)
            except Exception:
                explanation = template

            if intent not in VALID_INTENTS:
                intent = "operational_noise"

            return {
                "explanation": explanation,
                "intent": intent
            }

        # 2. Fallback Template for unmapped combinations (Never crashes or empty string)
        fallback_explanation = (
            f"Observed {params['class_name']} event ({params['activity_name']}) "
            f"with status {disposition} involving source {src_ip}."
        )

        return {
            "explanation": fallback_explanation,
            "intent": "operational_noise"
        }

    def generate_chained_narrative(self, events: List[Dict[str, Any]]) -> str:
        """Combine explanations of events in chronological causal order into a paragraph."""
        if not events:
            return "No causal incident events detected."

        explanations = []
        for idx, event in enumerate(events, 1):
            exp_data = self.explain_event(event)
            exp_text = exp_data["explanation"]

            # Format causal step transition
            if idx == 1:
                explanations.append(f"Initially, {exp_text[0].lower()}{exp_text[1:]}")
            else:
                explanations.append(f"Subsequently, {exp_text[0].lower()}{exp_text[1:]}")

        return " ".join(explanations)
