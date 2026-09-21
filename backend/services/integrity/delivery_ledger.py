"""
Delivery ledger: a tamper-evident record of what happened to every stored event at
every output, so TRACELOG can prove where each log line went.

Tables (created in storage/db.py):
    delivery_outputs  one row per output: when it was first configured and the first
                      event sequence number it owes (events stored earlier are not its)
    delivery_batches  one row per delivery outcome, hash-chained:
                        batch_hash = SHA-256(prev_hash : output : outcome : trigger : at : count : events_hash)
                        events_hash = SHA-256 of the batch's "sequence:uid" lines, in sequence order
    delivery_events   one row per event in a batch (output, sequence_num, event uid, outcome)

Outcomes:
    delivered      the destination accepted it (trigger: live, manual or auto re-send, recovery)
    dead_lettered  it went to the output's dead-letter file (trigger: live, queue_full, manual, auto)
    rerouted       a dead letter delivered through another output (recorded on the original output)
    filtered       the output's filter excludes it (trigger: filter)

An event's current state at an output is its latest outcome there. Editing, deleting
or reordering any of these rows breaks the chain, which verify() reports.
"""
import hashlib
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.services.storage import db as db_module

GENESIS = "0" * 64
OUTCOMES = ("delivered", "dead_lettered", "rerouted", "filtered")
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def event_key(ocsf: Dict[str, Any]) -> Optional[Tuple[int, str]]:
    md = ocsf.get("metadata") or {}
    seq, uid = md.get("sequence"), md.get("uid")
    if seq is None or (ocsf.get("unmapped") or {}).get("tracelog_test_event"):
        return None
    return int(seq), str(uid or "")


def events_hash(keys: Iterable[Tuple[int, str]]) -> str:
    body = "\n".join(f"{s}:{u}" for s, u in sorted(keys))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def batch_hash(prev: str, output: str, outcome: str, trigger: str, at: str, count: int, ev_hash: str) -> str:
    pre = f"{prev}:{output}:{outcome}:{trigger}:{at}:{count}:{ev_hash}"
    return hashlib.sha256(pre.encode("utf-8")).hexdigest()


class DeliveryLedger:
    """All writes go through one lock so the hash chain stays linear across output threads."""

    # ---- registration -----------------------------------------------------------------------
    @staticmethod
    def register_output(name: str, type_name: str, target: str) -> Dict[str, Any]:
        with _lock, db_module.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM delivery_outputs WHERE output = ?", (name,)).fetchone()
            if row:
                conn.execute("UPDATE delivery_outputs SET type = ?, target = ? WHERE output = ?",
                             (type_name, target, name))
                conn.commit()
                return dict(row)
            first = (conn.execute("SELECT MAX(sequence_num) FROM normalized_events").fetchone()[0] or 0) + 1
            conn.execute("INSERT INTO delivery_outputs (output, type, target, first_seq, added_at) "
                         "VALUES (?, ?, ?, ?, ?)", (name, type_name, target, first, _now()))
            conn.commit()
            return {"output": name, "type": type_name, "target": target, "first_seq": first, "added_at": _now()}

    # ---- recording ----------------------------------------------------------------------------
    @staticmethod
    def record(output: str, outcome: str, trigger: str, events: List[Dict[str, Any]],
               detail: str = "") -> Optional[int]:
        keys = [k for k in (event_key(e) for e in events) if k is not None]
        if not keys:
            return None
        at = _now()
        ev_hash = events_hash(keys)
        with _lock, db_module.db.get_connection() as conn:
            last = conn.execute("SELECT batch_hash FROM delivery_batches ORDER BY id DESC LIMIT 1").fetchone()
            prev = last[0] if last else GENESIS
            h = batch_hash(prev, output, outcome, trigger, at, len(keys), ev_hash)
            cur = conn.execute(
                "INSERT INTO delivery_batches (output, outcome, trigger, at, count, detail, events_hash, prev_hash, "
                "batch_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (output, outcome, trigger, at, len(keys), detail[:500], ev_hash, prev, h))
            batch_id = cur.lastrowid
            conn.executemany("INSERT INTO delivery_events (batch_id, output, sequence_num, event_uid, outcome) "
                             "VALUES (?, ?, ?, ?, ?)", [(batch_id, output, s, u, outcome) for s, u in keys])
            conn.commit()
        return batch_id

    # ---- recovery -----------------------------------------------------------------------------
    @staticmethod
    def owed_without_outcome(output: str, after_seq: int = 0, limit: int = 1000) -> List[Dict[str, Any]]:
        """Stored events this output owes but has no outcome for (queued or in flight when TRACELOG stopped)."""
        with db_module.db.get_connection() as conn:
            first = conn.execute("SELECT first_seq FROM delivery_outputs WHERE output = ?", (output,)).fetchone()
            if not first:
                return []
            rows = conn.execute(
                """SELECT n.sequence_num, n.normalized_json, s.name AS source_name
                   FROM normalized_events n
                   LEFT JOIN raw_logs r ON r.id = n.raw_id
                   LEFT JOIN sources s ON s.id = r.source_id
                   WHERE n.sequence_num >= ? AND n.sequence_num > ?
                     AND NOT EXISTS (SELECT 1 FROM delivery_events d
                                     WHERE d.output = ? AND d.sequence_num = n.sequence_num)
                   ORDER BY n.sequence_num LIMIT ?""", (first[0], after_seq, output, limit)).fetchall()
        return [dict(r) for r in rows]

    # ---- verification ---------------------------------------------------------------------------
    @staticmethod
    def verify() -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        expected_prev = GENESIS
        n = 0
        with db_module.db.get_connection() as conn:
            batches = conn.execute("SELECT * FROM delivery_batches ORDER BY id").fetchall()
            per_batch: Dict[int, List[Tuple[int, str, str]]] = {}
            for r in conn.execute("SELECT batch_id, sequence_num, event_uid, outcome FROM delivery_events"):
                per_batch.setdefault(r[0], []).append((r[1], r[2] or "", r[3]))
        head = GENESIS
        for b in batches:
            n += 1
            rows = per_batch.pop(b["id"], [])
            if b["prev_hash"] != expected_prev:
                issues.append({"batch": b["id"], "problem": "chain broken (a batch was removed or reordered)"})
            if len(rows) != b["count"] or events_hash((s, u) for s, u, _ in rows) != b["events_hash"]:
                issues.append({"batch": b["id"], "problem": "event rows changed, added or removed"})
            if any(o != b["outcome"] for _, _, o in rows):
                issues.append({"batch": b["id"], "problem": "an event's outcome was edited"})
            recomputed = batch_hash(b["prev_hash"], b["output"], b["outcome"], b["trigger"], b["at"], b["count"],
                                    b["events_hash"])
            if recomputed != b["batch_hash"]:
                issues.append({"batch": b["id"], "problem": "batch record edited"})
            expected_prev = b["batch_hash"]
            head = b["batch_hash"]
        for batch_id in per_batch:
            issues.append({"batch": batch_id, "problem": "event rows belong to a batch that no longer exists"})
        return {"is_valid": not issues, "batches": n, "head_hash": head, "issues": issues[:50],
                "issue_count": len(issues), "verified_at": _now()}

    # ---- reconciliation inputs --------------------------------------------------------------------
    @staticmethod
    def outputs() -> List[Dict[str, Any]]:
        with db_module.db.get_connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM delivery_outputs ORDER BY output")]

    @staticmethod
    def output_counts(output: str, first_seq: int, upto_seq: int) -> Dict[str, Any]:
        """Latest outcome per owed event, plus re-sends, duplicates and events not accounted for."""
        with db_module.db.get_connection() as conn:
            owed = conn.execute("SELECT COUNT(*) FROM normalized_events WHERE sequence_num BETWEEN ? AND ?",
                                (first_seq, upto_seq)).fetchone()[0]
            latest = dict(conn.execute(
                """SELECT d.outcome, COUNT(*) FROM delivery_events d
                   JOIN (SELECT MAX(rowid) AS r FROM delivery_events
                         WHERE output = ? AND sequence_num BETWEEN ? AND ? GROUP BY sequence_num) m
                     ON d.rowid = m.r
                   GROUP BY d.outcome""", (output, first_seq, upto_seq)).fetchall())
            resent = conn.execute(
                """SELECT COUNT(DISTINCT e.sequence_num) FROM delivery_events e JOIN delivery_batches b
                     ON b.id = e.batch_id
                   WHERE e.output = ? AND e.outcome = 'delivered' AND b.trigger IN ('manual', 'auto')
                     AND e.sequence_num BETWEEN ? AND ?""", (output, first_seq, upto_seq)).fetchone()[0]
            duplicates = conn.execute(
                """SELECT COUNT(*) FROM (SELECT sequence_num FROM delivery_events
                   WHERE output = ? AND outcome = 'delivered' AND sequence_num BETWEEN ? AND ?
                   GROUP BY sequence_num HAVING COUNT(*) > 1)""", (output, first_seq, upto_seq)).fetchone()[0]
            ever_dead = conn.execute(
                """SELECT COUNT(DISTINCT sequence_num) FROM delivery_events
                   WHERE output = ? AND outcome = 'dead_lettered' AND sequence_num BETWEEN ? AND ?""",
                (output, first_seq, upto_seq)).fetchone()[0]
        accounted = sum(latest.values())
        return {"owed": owed, "delivered": latest.get("delivered", 0), "rerouted": latest.get("rerouted", 0),
                "filtered": latest.get("filtered", 0), "dead_letter_waiting": latest.get("dead_lettered", 0),
                "resent": resent, "ever_dead_lettered": ever_dead, "duplicates": duplicates,
                "without_outcome": max(owed - accounted, 0)}

    @staticmethod
    def exceptions(limit: int = 25, scan: int = 5000) -> List[Dict[str, Any]]:
        """Outages, rejections, re-sends and re-routes as a timeline: consecutive records with the same
        output, outcome, trigger and reason are merged into one episode (first..last time, totals)."""
        with db_module.db.get_connection() as conn:
            rows = conn.execute(
                """SELECT id, output, outcome, trigger, at, count, detail FROM delivery_batches
                   WHERE NOT (outcome = 'delivered' AND trigger = 'live') AND outcome != 'filtered'
                   ORDER BY id DESC LIMIT ?""", (scan,)).fetchall()
        episodes: List[Dict[str, Any]] = []
        for r in reversed(rows):  # oldest first, so episodes read forwards in time
            key = (r["output"], r["outcome"], r["trigger"], r["detail"] or "")
            last = episodes[-1] if episodes else None
            if last and last["_key"] == key:
                last.update(to=r["at"], batches=last["batches"] + 1, count=last["count"] + r["count"])
            else:
                episodes.append({"_key": key, "output": r["output"], "outcome": r["outcome"], "trigger": r["trigger"],
                                 "detail": r["detail"] or "", "from": r["at"], "to": r["at"], "batches": 1,
                                 "count": r["count"]})
        out = []
        for e in reversed(episodes[-limit:]):  # newest first
            e.pop("_key")
            out.append(e)
        return out
