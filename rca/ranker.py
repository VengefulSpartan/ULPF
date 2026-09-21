import networkx as nx
from typing import List, Dict, Any, Tuple, Optional
import structlog

from core.explainer.explainer import SemanticExplainer

logger = structlog.get_logger()


class RCARanker:
    """Ranks root-cause candidate events combining earliest timestamp, downstream reachability,
    severity, and PageRank centrality.
    """

    def __init__(
        self,
        weight_time: float = 0.35,
        weight_reach: float = 0.30,
        weight_sev: float = 0.20,
        weight_pagerank: float = 0.15
    ):
        self.w_time = weight_time
        self.w_reach = weight_reach
        self.w_sev = weight_sev
        self.w_pr = weight_pagerank
        self.explainer = SemanticExplainer()

    def rank_root_causes(
        self,
        graph: nx.DiGraph,
        target_entity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Rank root cause candidates from temporal entity graph.
        
        Returns:
            List of ranked candidate dicts with rank, event_uuid, score, factors, and causal_chain.
        """
        event_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "event"]
        if not event_nodes:
            return []

        # 1. PageRank Centrality
        try:
            pagerank_scores = nx.pagerank(graph, alpha=0.85)
        except Exception:
            pagerank_scores = {n: 1.0 / graph.number_of_nodes() for n in graph.nodes()}

        # Filter events connected to target_entity if specified
        if target_entity:
            entity_node = f"entity_{target_entity}" if not target_entity.startswith("entity_") else target_entity
            if graph.has_node(entity_node):
                # Filter to events connected to entity
                connected = set(graph.neighbors(entity_node)).union(set(graph.predecessors(entity_node)))
                event_nodes = [n for n in event_nodes if n in connected]

        if not event_nodes:
            event_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "event"]

        timestamps = [graph.nodes[n]["time"] for n in event_nodes]
        min_time = min(timestamps) if timestamps else 0
        max_time = max(timestamps) if timestamps else 1
        time_span = max(1.0, float(max_time - min_time))

        total_event_count = len(event_nodes)
        candidates = []

        for node in event_nodes:
            node_data = graph.nodes[node]
            event_time = node_data["time"]
            sev_id = node_data.get("severity_id", 1)

            # Earliest Timestamp Score (1.0 for earliest, decreasing to 0.0 for latest)
            s_time = 1.0 - ((event_time - min_time) / time_span)

            # Downstream Reachability (count of downstream reachable event nodes)
            descendants = nx.descendants(graph, node)
            downstream_events = [d for d in descendants if graph.nodes[d].get("node_type") == "event"]
            s_reach = min(1.0, len(downstream_events) / max(1, total_event_count - 1))

            # Severity Score (scaled 1-5 to 0.2-1.0)
            s_sev = min(1.0, max(0.2, sev_id / 5.0))

            # PageRank Centrality
            s_pr = pagerank_scores.get(node, 0.0)

            # Composite Score
            total_score = (
                self.w_time * s_time +
                self.w_reach * s_reach +
                self.w_sev * s_sev +
                self.w_pr * s_pr
            )

            # Extract Causal Chain (chronological sequence of root cause + downstream events)
            causal_chain = [node_data.get("uuid")]
            if downstream_events:
                all_chain_nodes = [node] + list(downstream_events)
                sorted_chain_nodes = sorted(all_chain_nodes, key=lambda n: graph.nodes[n].get("time", 0))
                causal_chain = [
                    graph.nodes[n].get("uuid")
                    for n in sorted_chain_nodes
                    if graph.nodes[n].get("uuid")
                ]

            # Generate explanation and intent for candidate node
            raw_evt = node_data.get("raw_event", {})
            explanation_data = self.explainer.explain_event(raw_evt)

            # Generate chained narrative for causal chain events
            causal_events = []
            for uuid_item in causal_chain:
                # Find graph node for uuid_item
                matching_nodes = [
                    n for n, d in graph.nodes(data=True)
                    if d.get("uuid") == uuid_item and d.get("node_type") == "event"
                ]
                if matching_nodes:
                    causal_events.append(graph.nodes[matching_nodes[0]].get("raw_event", {}))

            chained_narrative = self.explainer.generate_chained_narrative(causal_events)

            candidates.append({
                "event_uuid": node_data.get("uuid"),
                "node_id": node,
                "score": round(total_score, 4),
                "factors": {
                    "time_score": round(s_time, 2),
                    "reachability_count": len(downstream_events),
                    "severity_id": sev_id,
                    "pagerank": round(s_pr, 4)
                },
                "causal_chain": causal_chain,
                "explanation": explanation_data["explanation"],
                "intent": explanation_data["intent"],
                "chained_narrative": chained_narrative,
                "raw_event": raw_evt
            })

        # Sort candidates descending by score
        candidates.sort(key=lambda c: c["score"], reverse=True)

        # Assign rank 1..N
        for idx, candidate in enumerate(candidates, 1):
            candidate["rank"] = idx

        logger.info("rca_ranking_completed", candidate_count=len(candidates), top_root_cause=candidates[0]["event_uuid"] if candidates else None)
        return candidates
