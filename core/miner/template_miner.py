import os
from typing import Dict, Any, List, Tuple, Optional
import structlog

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

logger = structlog.get_logger()


class TemplateMinerWrapper:
    """Wrapper around Drain3 for log template mining and variable extraction."""

    def __init__(self, config_path: Optional[str] = None):
        cfg = TemplateMinerConfig()
        cfg.load(config_path) if config_path and os.path.exists(config_path) else None
        cfg.profiling_enabled = False
        
        self.miner = TemplateMiner(config=cfg)

    def process_line(self, log_line: str) -> Dict[str, Any]:
        """Process a single log line, update template miner, and return mined template info."""
        result = self.miner.add_log_message(log_line)
        template_id = result["cluster_id"]
        template_mined = result["template_mined"]
        
        # Extract variables corresponding to <*>
        extracted_vars = self.miner.extract_parameters(template_mined, log_line)
        var_values = [v.value for v in extracted_vars] if extracted_vars else []

        return {
            "template_id": template_id,
            "template_mined": template_mined,
            "extracted_variables": var_values,
            "change_type": result["change_type"]
        }
