"""
Cross-source correlation: which events, from which devices, touch the same addresses close
together in time.

Everything this module reports is one of two things. An observed fact is a stored event, with
the hash of the raw line it came from. A relationship is a rule that held, reported with the
evidence that made it hold: which address two events share, how many seconds apart they are,
how many ports one host tried. There are no confidence scores. An earlier version attached
constants to its hypotheses (0.88, 0.92, 0.85, and 0.60 to 0.89 for the incident); nothing
measured them, so they were removed rather than dressed up. A relationship is a pattern that
matched, not a probability that something is an attack, and the page says so.

The rules, with their thresholds as named constants so the evidence can quote them:

  login then activity    a successful Authentication event, then, within LOGIN_FOLLOW_SECONDS,
                         an event from a different device that involves one of the login's
                         addresses (typically the address a VPN assigned)
  allowed then alert     a connection a device allowed, then, within ALERT_FOLLOW_SECONDS, a
                         Detection Finding from a different device on the same address pair
  port sweep             one source address reaching at least SWEEP_MIN_PORTS distinct
                         destination ports within SWEEP_SECONDS
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from backend.models.correlation import IncidentSummary, InferredRelationship, ObservedFact
from backend.services.storage.db import db

MAX_EVENTS = 200
LOGIN_FOLLOW_SECONDS = 1800
ALERT_FOLLOW_SECONDS = 600
SWEEP_SECONDS = 60
SWEEP_MIN_PORTS = 10

AUTHENTICATION, NETWORK_ACTIVITY, DETECTION_FINDING = 3002, 4001, 2004
SEVERITY_ORDER = ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"]
ALLOWED = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "success"}


def _addresses(row) -> Set[str]:
    return {a for a in (row["src_ip"], row["dst_ip"]) if a}


def _seconds(a, b) -> float:
    return (b["time_epoch_ms"] - a["time_epoch_ms"]) / 1000.0


def _endpoint(ip: Optional[str], port: Optional[int]) -> str:
    if not ip:
        return "?"
    return f"{ip}:{port}" if port is not None else ip


def _login_succeeded(row, data: Dict[str, Any]) -> bool:
    status = str(data.get("status") or "").lower()
    if status:
        return status == "success"
    return str(row["disposition"] or row["action"] or "").lower() in ALLOWED


def _device(row, data: Dict[str, Any]) -> str:
    if row["source_name"]:
        return row["source_name"]
    product = data.get("metadata", {}).get("product", {})
    return f"{product.get('vendor_name', 'Unknown')} {product.get('name', 'device')}"


class CorrelationEngine:

    @classmethod
    def _events(cls, pivot_ip: Optional[str], time_window_minutes: int) -> List[Any]:
        """The newest MAX_EVENTS current events inside the window that ends at the newest match."""
        where, args = "n.superseded_by IS NULL", []
        if pivot_ip:
            where += " AND (n.src_ip = ? OR n.dst_ip = ?)"
            args += [pivot_ip, pivot_ip]
        with db.get_connection() as conn:
            newest = conn.execute(f"SELECT MAX(n.time_epoch_ms) FROM normalized_events n WHERE {where}",
                                  args).fetchone()[0]
            if newest is None:
                return []
            rows = conn.execute(
                f"""
                SELECT n.*, r.raw_hash, r.source_id, s.name AS source_name
                FROM normalized_events n
                JOIN raw_logs r ON n.raw_id = r.id
                LEFT JOIN sources s ON s.id = r.source_id
                WHERE {where} AND n.time_epoch_ms >= ?
                ORDER BY n.time_epoch_ms DESC, n.sequence_num DESC
                LIMIT {MAX_EVENTS}
                """,
                args + [newest - max(1, time_window_minutes) * 60_000],
            ).fetchall()
        return list(reversed(rows))

    @classmethod
    def run_correlation(cls, pivot_ip: Optional[str] = None, time_window_minutes: int = 60) -> IncidentSummary:
        rows = cls._events(pivot_ip, time_window_minutes)
        if not rows:
            now = datetime.utcnow().isoformat()
            return IncidentSummary(
                title="No events found" + (f" involving {pivot_ip}" if pivot_ip else ""),
                severity="Unknown", start_time=now, end_time=now,
                entities={"ips": [], "users": [], "devices": []},
                recommendations=["Ingest logs from more than one perimeter device to correlate across them."])

        data = [json.loads(r["normalized_json"]) for r in rows]
        facts, ips, users, devices = [], set(), set(), set()
        for r, d in zip(rows, data):
            device = _device(r, d)
            product = d.get("metadata", {}).get("product", {})
            devices.add(device)
            ips |= _addresses(r)
            if r["user_name"]:
                users.add(r["user_name"])
            text = (f"[{device}] {r['class_name']}: {r['action'] or r['disposition'] or 'no action'} "
                    f"{_endpoint(r['src_ip'], r['src_port'])} -> {_endpoint(r['dst_ip'], r['dst_port'])}"
                    f"{' (' + r['protocol'] + ')' if r['protocol'] else ''}.")
            if r["finding_title"]:
                text += f" Signature: '{r['finding_title']}'."
            if r["user_name"]:
                text += f" User: '{r['user_name']}'."
            facts.append(ObservedFact(
                event_id=r["id"], sequence_num=r["sequence_num"], timestamp=r["time"],
                source_vendor=product.get("vendor_name", "Unknown"), source_product=product.get("name", "Device"),
                event_class=r["class_name"], src_ip=r["src_ip"], dst_ip=r["dst_ip"], user=r["user_name"],
                action=r["action"] or r["disposition"], severity=r["severity"], raw_hash=r["raw_hash"],
                fact_description=text))

        links: List[InferredRelationship] = []
        links += cls._login_then_activity(rows, data)
        links += cls._allowed_then_alert(rows, data)
        links += cls._port_sweeps(rows)

        kinds = {l.relationship_type for l in links}
        severity = max((r["severity"] for r in rows),
                       key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0)
        where = f" involving {pivot_ip}" if pivot_ip else ""
        incident = IncidentSummary(
            title=f"{len(rows)} events from {len(devices)} device{'s' if len(devices) != 1 else ''}{where}",
            severity=severity,
            start_time=rows[0]["time"], end_time=rows[-1]["time"],
            entities={"ips": sorted(ips), "users": sorted(users), "devices": sorted(devices)},
            observed_facts=facts,
            inferred_relationships=links,
            attack_phases=sorted({PATTERN_NAMES[k] for k in kinds}),
            # a technique is named only where the rule is that technique's definition
            mitre_tactics=["TA0007 Discovery (T1046 Network Service Discovery)"] if "PORT_SWEEP" in kinds else [],
            recommendations=cls._recommendations(links),
        )
        cls._store(incident)
        return incident

    # ---------------------------------------------------------------------------------------------
    # the rules
    # ---------------------------------------------------------------------------------------------
    @staticmethod
    def _login_then_activity(rows, data) -> List[InferredRelationship]:
        out = []
        for i, (login, d) in enumerate(zip(rows, data)):
            if login["class_uid"] != AUTHENTICATION or not _login_succeeded(login, d):
                continue
            addresses = _addresses(login)
            later = [r for r in rows[i + 1:]
                     if r["source_id"] != login["source_id"] and r["class_uid"] in (NETWORK_ACTIVITY, DETECTION_FINDING)
                     and 0 <= _seconds(login, r) <= LOGIN_FOLLOW_SECONDS and _addresses(r) & addresses]
            if not later:
                continue
            first = later[0]
            shared = sorted(_addresses(first) & addresses)
            gap = _seconds(login, first)
            who = f"'{login['user_name']}'" if login["user_name"] else "a user"
            out.append(InferredRelationship(
                source_event_ids=[login["id"]] + [r["id"] for r in later],
                relationship_type="LOGIN_THEN_ACTIVITY",
                time_delta_seconds=gap,
                shared_entities=shared,
                evidence=[f"login by {who} succeeded (event #{login['sequence_num']})",
                          f"shared address {', '.join(shared)}",
                          f"first later event {gap:.0f} s after the login, from a different device",
                          f"{len(later)} event{'s' if len(later) != 1 else ''} from other devices within "
                          f"{LOGIN_FOLLOW_SECONDS // 60} min"],
                hypothesis=(f"{who} logged in from {login['src_ip'] or '?'}; {gap:.0f} s later another device "
                            f"logged {_endpoint(first['src_ip'], first['src_port'])} -> "
                            f"{_endpoint(first['dst_ip'], first['dst_port'])}, which shares {', '.join(shared)}."),
                rationale=("The address match and the timing are what was observed. They do not prove it was the "
                           "same session: an address reused by NAT or DHCP would look the same."),
            ))
        return out

    @staticmethod
    def _allowed_then_alert(rows, data) -> List[InferredRelationship]:
        out = []
        for j, alert in enumerate(rows):
            if alert["class_uid"] != DETECTION_FINDING or not (alert["src_ip"] and alert["dst_ip"]):
                continue
            pair = {alert["src_ip"], alert["dst_ip"]}
            before = [r for r in rows[:j]
                      if r["class_uid"] == NETWORK_ACTIVITY and r["source_id"] != alert["source_id"]
                      and str(r["disposition"] or r["action"] or "").lower() in ALLOWED
                      and _addresses(r) == pair and 0 <= _seconds(r, alert) <= ALERT_FOLLOW_SECONDS]
            if not before:
                continue
            conn = before[-1]
            gap = _seconds(conn, alert)
            out.append(InferredRelationship(
                source_event_ids=[conn["id"], alert["id"]],
                relationship_type="ALLOWED_THEN_ALERT",
                time_delta_seconds=gap,
                shared_entities=sorted(pair),
                evidence=[f"same address pair {alert['src_ip']} and {alert['dst_ip']}",
                          f"connection allowed (event #{conn['sequence_num']}) {gap:.0f} s before the alert "
                          f"(event #{alert['sequence_num']})",
                          f"alert from a different device: '{alert['finding_title'] or 'no signature name'}'"],
                hypothesis=(f"A connection between {alert['src_ip']} and {alert['dst_ip']} was allowed, and {gap:.0f} s "
                            f"later a sensor raised '{alert['finding_title'] or 'an alert'}' on the same pair."),
                rationale=("Same two addresses, alert after the allowed connection. The logs do not show that the "
                           "alert came from that connection rather than another one between the same hosts."),
            ))
        return out

    @staticmethod
    def _port_sweeps(rows) -> List[InferredRelationship]:
        out = []
        by_source: Dict[str, List[Any]] = {}
        for r in rows:
            if r["src_ip"] and r["dst_port"] is not None:
                by_source.setdefault(r["src_ip"], []).append(r)
        for src, events in by_source.items():
            start = 0
            for end in range(len(events)):
                while _seconds(events[start], events[end]) > SWEEP_SECONDS:
                    start += 1
                window = events[start:end + 1]
                ports = {e["dst_port"] for e in window}
                if len(ports) >= SWEEP_MIN_PORTS:
                    hosts = {e["dst_ip"] for e in window if e["dst_ip"]}
                    span = _seconds(window[0], window[-1])
                    out.append(InferredRelationship(
                        source_event_ids=[e["id"] for e in window],
                        relationship_type="PORT_SWEEP",
                        time_delta_seconds=span,
                        shared_entities=[src],
                        evidence=[f"{len(ports)} distinct destination ports on {len(hosts)} "
                                  f"host{'s' if len(hosts) != 1 else ''} in {span:.1f} s",
                                  f"threshold: {SWEEP_MIN_PORTS} ports within {SWEEP_SECONDS} s"],
                        hypothesis=f"{src} tried {len(ports)} different destination ports in {span:.1f} s.",
                        rationale=("That is what a port scan looks like. A busy legitimate client (a monitoring "
                                   "system, a proxy) can look the same."),
                    ))
                    break  # one report per source address
        return out

    @staticmethod
    def _recommendations(links: List[InferredRelationship]) -> List[str]:
        recs = []
        for l in links:
            if l.relationship_type == "LOGIN_THEN_ACTIVITY":
                recs.append(f"Confirm with the account owner that the session behind {', '.join(l.shared_entities)} "
                            "was theirs; revoke it if not.")
            elif l.relationship_type == "ALLOWED_THEN_ALERT":
                recs.append(f"Pull the sensor's payload for the alert between {' and '.join(l.shared_entities)} and "
                            "review the rule that allowed the connection.")
            elif l.relationship_type == "PORT_SWEEP":
                recs.append(f"Check whether {l.shared_entities[0]} is a known scanner; block it at the perimeter "
                            "if not.")
        recs.append("Verify the integrity chain before these events are used as evidence.")
        return list(dict.fromkeys(recs))

    @staticmethod
    def _store(incident: IncidentSummary) -> None:
        with db.get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO incidents (incident_id, title, severity, start_time, end_time, data_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                (incident.incident_id, incident.title, incident.severity, incident.start_time, incident.end_time,
                 json.dumps(incident.model_dump())))
            conn.commit()


PATTERN_NAMES = {"LOGIN_THEN_ACTIVITY": "Activity after a login", "ALLOWED_THEN_ALERT": "Alert on an allowed connection",
                 "PORT_SWEEP": "Port sweep"}
