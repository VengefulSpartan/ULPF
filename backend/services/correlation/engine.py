import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.services.storage.db import db
from backend.models.correlation import IncidentSummary, ObservedFact, InferredRelationship

class CorrelationEngine:
    """
    USP 3: Cross-Source Root Cause Analysis (RCA) Engine.
    Correlates perimeter logs across firewalls, routers, VPNs, and IDS/IPS devices.
    Strictly separates Observed Facts from Inferred Relationships.
    """

    @classmethod
    def run_correlation(
        cls,
        pivot_ip: Optional[str] = None,
        time_window_minutes: int = 60
    ) -> IncidentSummary:
        """
        Scans normalized events, connects cross-source activity sharing entities (IP, user),
        constructs a causal graph, and produces an evidence-backed incident report.
        """
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Fetch events
            if pivot_ip:
                cursor.execute(
                    """
                    SELECT n.*, r.raw_hash
                    FROM normalized_events n
                    JOIN raw_logs r ON n.raw_id = r.id
                    WHERE n.src_ip = ? OR n.dst_ip = ?
                    ORDER BY n.time_epoch_ms ASC
                    LIMIT 200
                    """,
                    (pivot_ip, pivot_ip)
                )
            else:
                cursor.execute(
                    """
                    SELECT n.*, r.raw_hash
                    FROM normalized_events n
                    JOIN raw_logs r ON n.raw_id = r.id
                    ORDER BY n.time_epoch_ms ASC
                    LIMIT 200
                    """
                )
            rows = cursor.fetchall()

        if not rows:
            return IncidentSummary(
                title="No Correlated Events Found",
                severity="Low",
                confidence_score=0.0,
                start_time=datetime.utcnow().isoformat(),
                end_time=datetime.utcnow().isoformat(),
                entities={"ips": [], "users": [], "devices": []},
                observed_facts=[],
                inferred_relationships=[],
                attack_phases=[],
                mitre_tactics=[],
                recommendations=["Ingest perimeter network logs from multiple devices to generate cross-source correlations."]
            )

        observed_facts: List[ObservedFact] = []
        all_ips = set()
        all_users = set()
        all_devices = set()

        for r in rows:
            data = json.loads(r["normalized_json"])
            vendor = data.get("metadata", {}).get("product", {}).get("vendor_name", "Unknown")
            product = data.get("metadata", {}).get("product", {}).get("name", "Device")
            all_devices.add(f"{vendor} {product}")

            src_ip = r["src_ip"]
            dst_ip = r["dst_ip"]
            user = r["user_name"]

            if src_ip:
                all_ips.add(src_ip)
            if dst_ip:
                all_ips.add(dst_ip)
            if user:
                all_users.add(user)

            # Construct verified fact
            fact_desc = (
                f"[{vendor} {product}] {r['class_name']}: "
                f"Action '{r['action'] or r['disposition']}' on {src_ip}:{r['src_port']} -> {dst_ip}:{r['dst_port']} "
                f"({r['protocol'] or 'IP'})."
            )
            if r["finding_title"]:
                fact_desc += f" Signature: '{r['finding_title']}'."
            if user:
                fact_desc += f" User: '{user}'."

            observed_facts.append(ObservedFact(
                event_id=r["id"],
                sequence_num=r["sequence_num"],
                timestamp=r["time"],
                source_vendor=vendor,
                source_product=product,
                event_class=r["class_name"],
                src_ip=src_ip,
                dst_ip=dst_ip,
                user=user,
                action=r["action"] or r["disposition"],
                severity=r["severity"],
                raw_hash=r["raw_hash"],
                fact_description=fact_desc
            ))

        # Inferred relationships across sources
        inferred: List[InferredRelationship] = []
        attack_phases = set()
        mitre_tactics = set()

        for i in range(len(rows) - 1):
            curr = rows[i]
            nxt = rows[i + 1]

            curr_data = json.loads(curr["normalized_json"])
            nxt_data = json.loads(nxt["normalized_json"])

            delta_sec = abs(nxt["time_epoch_ms"] - curr["time_epoch_ms"]) / 1000.0

            # 1. VPN auth followed by internal scan or firewall activity
            if curr["class_uid"] == 3002 and nxt["class_uid"] == 4001:
                if delta_sec < 1800: # within 30 min
                    attack_phases.add("Initial Access -> Lateral Recon")
                    mitre_tactics.add("TA0001 Initial Access")
                    mitre_tactics.add("TA0007 Discovery")
                    inferred.append(InferredRelationship(
                        source_event_ids=[curr["id"], nxt["id"]],
                        relationship_type="TEMPORAL_AUTHENTICATION_PIVOT",
                        confidence=0.88,
                        time_delta_seconds=delta_sec,
                        hypothesis=f"User session from {curr['src_ip']} successfully authenticated via VPN, followed {delta_sec:.1f}s later by outbound network connection to {nxt['dst_ip']}.",
                        rationale="Temporal proximity and matching network ingress point suggest subsequent network activity was spawned by the authenticated session. (Analytical hypothesis, not absolute proof of intent)."
                    ))

            # 2. Firewall traffic followed by IDS Alert
            if curr["class_uid"] == 4001 and nxt["class_uid"] == 2004:
                if (curr["src_ip"] == nxt["src_ip"] or curr["dst_ip"] == nxt["dst_ip"]) and delta_sec < 600:
                    attack_phases.add("Exploitation Activity")
                    mitre_tactics.add("TA0008 Lateral Movement")
                    inferred.append(InferredRelationship(
                        source_event_ids=[curr["id"], nxt["id"]],
                        relationship_type="RECON_TO_EXPLOIT",
                        confidence=0.92,
                        time_delta_seconds=delta_sec,
                        hypothesis=f"Connection permitted by firewall preceded IDS signature alert '{nxt['finding_title']}' on endpoint {nxt['dst_ip']} within {delta_sec:.1f}s.",
                        rationale="Direct IP match and temporal convergence provide strong circumstantial link that the permitted session carried the malicious payload."
                    ))

            # 3. Port scan detection across same src_ip to multiple ports/dsts
            if curr["src_ip"] and nxt["src_ip"] and curr["src_ip"] == nxt["src_ip"]:
                if curr["dst_port"] != nxt["dst_port"] and delta_sec < 10:
                    attack_phases.add("Network Reconnaissance")
                    mitre_tactics.add("TA0007 Discovery")
                    inferred.append(InferredRelationship(
                        source_event_ids=[curr["id"], nxt["id"]],
                        relationship_type="PORT_SCAN_PROXIMITY",
                        confidence=0.85,
                        time_delta_seconds=delta_sec,
                        hypothesis=f"Host {curr['src_ip']} generated rapid connections across ports ({curr['dst_port']} -> {nxt['dst_port']}) in {delta_sec:.1f}s.",
                        rationale="High frequency connection attempts across multiple ports indicate automated port scanning behavior."
                    ))

        # Determine overall severity & confidence
        if any(f.severity in ["Critical", "High"] for f in observed_facts):
            overall_sev = "High"
            conf = 0.89 if inferred else 0.75
        elif any(f.severity == "Medium" for f in observed_facts):
            overall_sev = "Medium"
            conf = 0.80 if inferred else 0.65
        else:
            overall_sev = "Low"
            conf = 0.60

        incident = IncidentSummary(
            title=f"Cross-Source Perimeter Incident: Multi-Device Correlation ({len(all_devices)} Devices)",
            severity=overall_sev,
            confidence_score=conf,
            start_time=rows[0]["time"],
            end_time=rows[-1]["time"],
            entities={
                "ips": sorted(list(all_ips)),
                "users": sorted(list(all_users)),
                "devices": sorted(list(all_devices))
            },
            observed_facts=observed_facts,
            inferred_relationships=inferred,
            attack_phases=sorted(list(attack_phases)),
            mitre_tactics=sorted(list(mitre_tactics)),
            recommendations=[
                "Isolate suspicious source IP endpoints on network perimeter switch/firewall.",
                "Revoke and audit credentials associated with the authenticated VPN session.",
                "Review IDS payload captures for the flagged exploit signatures.",
                "Verify cryptographic hash chain in Integrity Ledger to ensure evidence has not been tampered with."
            ]
        )

        # Persist incident to DB
        with db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (incident_id, title, severity, confidence_score, start_time, end_time, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.severity,
                    incident.confidence_score,
                    incident.start_time,
                    incident.end_time,
                    json.dumps(incident.model_dump())
                )
            )
            conn.commit()

        return incident
