import networkx as nx
from typing import List, Dict, Any, Tuple, Set, Optional
import structlog

from rca.extractor import EntityExtractor

logger = structlog.get_logger()


class TemporalEntityGraph:
    """Builds a temporal directed entity graph using NetworkX."""

    def __init__(self, window_seconds: float = 300.0):
        self.window_seconds = window_seconds
        self.graph = nx.DiGraph()
        self.extractor = EntityExtractor()

    def build_graph(self, events: List[Dict[str, Any]]) -> nx.DiGraph:
        """Build directed temporal graph connecting events and entities."""
        self.graph.clear()
        
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.get("time", 0))

        event_entities_map: Dict[str, Set[str]] = {}

        # 1. Add Event & Entity Nodes
        for event in sorted_events:
            raw_ref = event.get("raw_ref", {})
            event_uuid = raw_ref.get("uuid") or str(event.get("time", 0))
            event_node = f"event_{event_uuid}"

            dt_time = event.get("time", 0)
            sev_id = event.get("severity_id", 1)

            self.graph.add_node(
                event_node,
                node_type="event",
                uuid=event_uuid,
                time=dt_time,
                severity_id=sev_id,
                class_name=event.get("class_name", "Unknown"),
                disposition=event.get("disposition", "UNKNOWN"),
                raw_event=event
            )

            # Extract entities
            entities = self.extractor.extract_entities(event)
            all_entity_keys = set()

            for e_type, values in entities.items():
                for val in values:
                    entity_node = f"entity_{e_type}_{val}"
                    all_entity_keys.add(entity_node)

                    if not self.graph.has_node(entity_node):
                        self.graph.add_node(
                            entity_node,
                            node_type="entity",
                            entity_type=e_type,
                            entity_value=val
                        )

                    # Connect event to entity
                    self.graph.add_edge(event_node, entity_node, relationship="has_entity")
                    self.graph.add_edge(entity_node, event_node, relationship="entity_in")

            event_entities_map[event_node] = all_entity_keys

        # 2. Add Directed Temporal Causal Edges between Events sharing entities
        event_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "event"]

        for i in range(len(event_nodes)):
            node_a = event_nodes[i]
            time_a = self.graph.nodes[node_a]["time"]
            entities_a = event_entities_map.get(node_a, set())

            for j in range(i + 1, len(event_nodes)):
                node_b = event_nodes[j]
                time_b = self.graph.nodes[node_b]["time"]
                entities_b = event_entities_map.get(node_b, set())

                time_diff = time_b - time_a
                if 0 <= time_diff <= self.window_seconds:
                    shared_entities = entities_a.intersection(entities_b)
                    if shared_entities:
                        # Directed temporal edge A -> B
                        self.graph.add_edge(
                            node_a,
                            node_b,
                            relationship="temporal_causal",
                            time_delta=time_diff,
                            shared_entities=list(shared_entities)
                        )

        logger.info(
            "temporal_graph_built",
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
            event_nodes=len(event_nodes)
        )
        return self.graph
