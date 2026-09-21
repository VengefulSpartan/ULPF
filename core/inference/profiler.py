from typing import List, Dict, Any, Tuple
from collections import defaultdict
import structlog

from core.inference.detectors import infer_single_value_type

logger = structlog.get_logger()


class VariableProfiler:
    """Profiles extracted variable positions across a sample window to infer high-confidence types."""

    def profile_variable_positions(self, sample_variables: List[List[str]]) -> List[Dict[str, Any]]:
        """Profile variable positions across sample window.
        
        Args:
            sample_variables: List of variable value lists extracted per log message.
            
        Returns:
            List of slot profile dicts containing slot_index, inferred_type, confidence, sample_values.
        """
        if not sample_variables:
            return []

        num_slots = len(sample_variables[0]) if sample_variables else 0
        slot_profiles = []

        for slot_idx in range(num_slots):
            slot_values = [vars_list[slot_idx] for vars_list in sample_variables if len(vars_list) > slot_idx]
            
            type_confidence_sums = defaultdict(float)
            type_counts = defaultdict(int)

            for val in slot_values:
                t_name, conf = infer_single_value_type(val)
                type_confidence_sums[t_name] += conf
                type_counts[t_name] += 1

            # Select dominant high-confidence type
            best_type = "unknown"
            best_avg_conf = 0.0

            total_samples = len(slot_values)
            for t_name, count in type_counts.items():
                avg_conf = (type_confidence_sums[t_name] / total_samples)
                if avg_conf > best_avg_conf:
                    best_type = t_name
                    best_avg_conf = avg_conf

            slot_profiles.append({
                "slot_index": slot_idx,
                "inferred_type": best_type,
                "confidence": round(best_avg_conf, 2),
                "total_samples": total_samples,
                "sample_values": list(set(slot_values))[:5]
            })

            logger.info(
                "slot_profiled",
                slot_index=slot_idx,
                inferred_type=best_type,
                confidence=best_avg_conf
            )

        return slot_profiles
