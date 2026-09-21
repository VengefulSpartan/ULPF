import os
import yaml
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class ParserPlugin:
    """Represents a loaded parser plugin definition."""

    def __init__(self, data: Dict[str, Any], file_path: str):
        self.parser_id: str = data.get("parser_id", "unknown_plugin")
        self.version: str = data.get("version", "1.0.0")
        self.status: str = data.get("status", "active")
        self.template_mined: str = data.get("template_mined", "")
        self.field_mappings: list = data.get("field_mappings", [])
        self.file_path: str = file_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parser_id": self.parser_id,
            "version": self.version,
            "status": self.status,
            "template_mined": self.template_mined,
            "field_mappings": self.field_mappings
        }


class PluginRegistry:
    """Manages versioning, loading, and hot-reloading parser plugins in core/plugins/."""

    def __init__(self, plugins_dir: Optional[str] = None):
        if plugins_dir is None:
            self.plugins_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        else:
            self.plugins_dir = os.path.abspath(plugins_dir)

        os.makedirs(self.plugins_dir, exist_ok=True)
        self.active_plugins: Dict[str, ParserPlugin] = {}
        self.reload_plugins()

    def reload_plugins(self) -> None:
        """Scan plugins directory and hot-reload all versioned YAML plugins."""
        self.active_plugins.clear()
        
        for root, _, files in os.walk(self.plugins_dir):
            for filename in files:
                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = yaml.safe_load(f)
                            if isinstance(content, dict) and "parser_id" in content:
                                plugin = ParserPlugin(content, file_path)
                                self.active_plugins[plugin.parser_id] = plugin
                                logger.info(
                                    "plugin_loaded",
                                    parser_id=plugin.parser_id,
                                    version=plugin.version,
                                    file_path=file_path
                                )
                    except Exception as exc:
                        logger.error("plugin_load_failed", file_path=file_path, error=str(exc))

    def get_plugin(self, parser_id: str) -> Optional[ParserPlugin]:
        return self.active_plugins.get(parser_id)

    def confirm_plugin(self, draft_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyst confirms or corrects a draft plugin mapping into a versioned plugin."""
        parser_id = draft_payload.get("parser_id", "custom_parser")
        version = draft_payload.get("version", "1.0.0")
        if "draft" in version:
            version = "1.0.0"

        confirmed_plugin_dict = {
            "parser_id": parser_id,
            "version": version,
            "status": "confirmed_active",
            "template_mined": draft_payload.get("template_mined", ""),
            "field_mappings": draft_payload.get("field_mappings", [])
        }

        filename = f"{parser_id}_v{version}.yaml"
        target_path = os.path.join(self.plugins_dir, filename)

        with open(target_path, "w", encoding="utf-8") as f:
            yaml.dump(confirmed_plugin_dict, f, sort_keys=False, default_flow_style=False)

        logger.info("plugin_confirmed_and_persisted", parser_id=parser_id, version=version, path=target_path)

        # Hot-reload registry
        self.reload_plugins()

        return {
            "status": "confirmed",
            "parser_id": parser_id,
            "version": version,
            "file_path": target_path
        }
