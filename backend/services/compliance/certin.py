"""
CERT-In mode: what TRACELOG can do towards the CERT-In directions of 28 April 2022.

The directions ask service providers, intermediaries, data centres, body corporates and
government organisations to
- keep the logs of their ICT systems for a rolling 180 days, within Indian jurisdiction
  (firewall, IPS, VPN, proxy and similar logs among them, successful and failed events both);
- report the cyber incidents listed in their Annexure I to CERT-In within 6 hours of noticing
  them (incident@cert-in.org.in, with the CERT-In incident reporting form);
- synchronise their clocks to NIC or NPL time servers.

TRACELOG keeps every line it receives and never deletes one on its own. In CERT-In mode it also
refuses to delete stored events from the dashboard, and it shows how many days the archive holds.
From a correlation result it drafts the facts an incident report needs: which Annexure I types
the evidence points to (as suggestions, with the reason), when it was noticed and when the
6-hour window closes, what was affected, the indicators, the timeline, and the evidence kept.
A person decides what to report and sends it: the draft is not a submission.
"""
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.services.evidence.bundle import _raw_bytes, _sha, collect, ist
from backend.services.compliance.certin_types import INCIDENT_TYPES, suggest_types
from backend.services.storage import db as db_module

REPORT_WITHIN = timedelta(hours=6)
REPORT_TO = "incident@cert-in.org.in"
FORM_URL = "https://www.cert-in.org.in/PDF/certinirform.pdf"
NTP_SERVERS = ("samay1.nic.in", "samay2.nic.in", "time.nplindia.org")

BLOCKED = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "reset", "fail", "failure"}
ALLOWED = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "success",
           "close", "closed", "start"}   # FortiGate logs a finished allowed session as action=close


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                 "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def _private(ip: str) -> Optional[bool]:
    """An organisation's own address space (RFC 1918, CGNAT, loopback, link-local, IPv6 ULA). Documentation
    ranges such as 198.51.100.0/24 count as external: they stand in for public addresses."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(a in n for n in _INTERNAL if n.version == a.version)


def deletion_allowed() -> bool:
    return not settings.CERTIN_MODE


# --------------------------------------------------------------------------------------- retention
def retention_status() -> Dict[str, Any]:
    with db_module.db.get_connection() as conn:
        oldest, newest, lines = conn.execute(
            "SELECT MIN(COALESCE(received_at, ingested_at)), MAX(COALESCE(received_at, ingested_at)), COUNT(*) "
            "FROM raw_logs").fetchone()
        outcomes = {r[0]: r[1] for r in conn.execute(
            "SELECT LOWER(COALESCE(disposition, action, '')), COUNT(*) FROM normalized_events "
            "WHERE superseded_by IS NULL GROUP BY 1").fetchall()}
    first = _parse(oldest)
    days = round((_now() - first).total_seconds() / 86400, 1) if first else 0.0
    kept = settings.RETENTION_DAYS
    return {
        "certin_mode": settings.CERTIN_MODE, "retention_days": kept,
        "lines_kept": lines, "oldest_received": oldest, "newest_received": newest,
        "oldest_received_ist": ist(first) if first else None, "days_held": days,
        "full_window_held": days >= kept,
        "deletion_blocked": not deletion_allowed(),
        "data_location": settings.DATA_LOCATION or None,
        "successful_events": sum(n for k, n in outcomes.items() if k in ALLOWED),
        "failed_or_blocked_events": sum(n for k, n in outcomes.items() if k in BLOCKED),
        "clock_sources": list(NTP_SERVERS),
        "summary": (f"{lines:,} lines kept since {ist(first)} ({days:g} of {kept} days)" if first
                    else "Nothing stored yet"),
    }


# --------------------------------------------------------------------------------------- incident report
def _incident(incident_id: str) -> Dict[str, Any]:
    with db_module.db.get_connection() as conn:
        row = conn.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise ValueError(f"no incident {incident_id}")
    return json.loads(row[0])


def draft_report(incident_id: str, org: Optional[Dict[str, str]] = None, noticed_at: Optional[str] = None,
                 types: Optional[List[str]] = None) -> Dict[str, Any]:
    incident = _incident(incident_id)
    facts = incident.get("observed_facts") or []
    if not facts:
        raise ValueError("the incident has no events to report")
    org = {k: (v or "").strip() for k, v in (org or {}).items()}
    seqs = [f["sequence_num"] for f in facts]
    got = collect(seqs)
    rows = {r["sequence_num"]: r for r in got["rows"]}

    # when it happened, and when TRACELOG noticed: the first detection it received (else the first event)
    times = [t for t in (_parse(f.get("timestamp")) for f in facts) if t]
    detections = [rows[s] for s in seqs if rows[s]["class_name"] == "Detection Finding"]
    basis = detections or [rows[s] for s in seqs]
    received = sorted(t for t in (_parse(r["received_at"] or r["ingested_at"]) for r in basis) if t)
    noticed = _parse(noticed_at) or (received[0] if received else _now())
    deadline = noticed + REPORT_WITHIN
    left = deadline - _now()

    internal, external, users = set(), set(), set()
    for f in facts:
        for ip in (f.get("src_ip"), f.get("dst_ip")):
            if ip:
                (internal if _private(ip) else external).add(ip)
        if f.get("user"):
            users.add(f["user"])
    acted = {"blocked": 0, "allowed": 0, "other": 0}
    for f in facts:
        a = str(f.get("action") or "").lower()
        acted["blocked" if a in BLOCKED else "allowed" if a in ALLOWED else "other"] += 1
    signatures = sorted({r["finding_title"] for r in rows.values() if r["finding_title"]})

    suggested = suggest_types(incident)
    chosen = [{"code": c, "type": INCIDENT_TYPES[c]} for c in (types or []) if c in INCIDENT_TYPES] or \
        [{"code": s["code"], "type": s["type"]} for s in suggested]
    intact = sum(1 for r in rows.values() if _sha(_raw_bytes(r)) == r["raw_hash"] and _sha(
        f"{r['prev_hash']}:{r['sequence_num']}:{r['raw_hash']}:{r['normalized_json'].strip()}".encode("utf-8"))
        == r["record_hash"])
    sealed = sum(1 for p in got["proofs"].values() if p)
    witnesses = sorted({s.get("name") for p in got["proofs"].values() if p for s in p["checkpoint"]["signatures"]
                        if s.get("role") == "witness"})
    now = _now()
    return {
        "report_id": f"CERTIN-DRAFT-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2).upper()}",
        "generated_at": now.isoformat(timespec="seconds"), "generated_at_ist": ist(now),
        "status": "Draft prepared by TRACELOG. Review it, complete the CERT-In incident reporting form and send it "
                  f"to {REPORT_TO}. TRACELOG sends nothing.",
        "report_to": REPORT_TO, "form": FORM_URL,
        "reporting_entity": {k: org.get(k, "") for k in ("organisation", "sector", "address", "contact_name",
                                                          "designation", "phone", "email")},
        "incident": {
            "incident_id": incident_id, "title": incident.get("title"), "severity": incident.get("severity"),
            "types": chosen, "suggested_types": suggested,
            "first_event": min(times).isoformat() if times else None,
            "first_event_ist": ist(min(times)) if times else None,
            "last_event_ist": ist(max(times)) if times else None,
            "noticed_at": noticed.isoformat(timespec="seconds"), "noticed_at_ist": ist(noticed),
            "noticed_basis": ("the first detection TRACELOG received" if detections else
                              "the first event TRACELOG received") if not noticed_at else "entered by the reporter",
            "report_by": deadline.isoformat(timespec="seconds"), "report_by_ist": ist(deadline),
            "hours_left": round(left.total_seconds() / 3600, 1),
            "overdue": left.total_seconds() < 0,
        },
        "affected": {"internal_addresses": sorted(internal), "users": sorted(users),
                     "devices_reporting": (incident.get("entities") or {}).get("devices", [])},
        "indicators": {"external_addresses": sorted(external), "signatures": signatures},
        "actions_observed": acted,
        "timeline": [{"sequence_num": f["sequence_num"], "time_ist": ist(_parse(f.get("timestamp"))),
                      "device": f"{f.get('source_vendor')} {f.get('source_product')}", "what": f.get("fact_description"),
                      "raw_sha256": f.get("raw_hash")} for f in facts[:30]],
        "timeline_total": len(facts),
        "rule_matches": [{"rule": l.get("relationship_type"), "what": l.get("hypothesis"),
                          "limits": l.get("rationale")} for l in incident.get("inferred_relationships") or []],
        "next_steps": incident.get("recommendations") or [],
        "evidence": {"records": len(rows), "first_seq": min(seqs), "last_seq": max(seqs),
                     "records_matching_their_hashes": intact, "in_signed_checkpoints": sealed, "witnesses": witnesses,
                     "bundle": f"/api/evidence/bundle.zip?incident_id={incident_id}"},
        "retention": retention_status(),
        "clock": f"Timestamps are as the devices and this server recorded them. CERT-In asks for clocks synchronised "
                 f"to {', '.join(NTP_SERVERS)}.",
    }
