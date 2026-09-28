"""
Signed checkpoints: blocks over the hash chain, countersigned by witnesses.

The hash chain (ledger.py) catches a record that was changed, removed or reordered. It does not
catch someone with write access to the database who changes a record and then recomputes every
record hash after it: the recomputed chain is consistent again. Checkpoints close that gap.

- Every CHECKPOINT_SIZE records (and, on a timer, whatever is left) the collector seals the
  records not yet covered: it computes their Merkle root (merkle.py), writes a small body that
  names the range, the root and the previous checkpoint's hash, and signs the body with its own
  keys (Ed25519, plus ML-DSA-65 where available; signing.py). The checkpoints form their own
  chain, block after block, each one committing to all the records before it.
- Each checkpoint is then sent to the witnesses (backend/witness.py): separate services, meant to
  run on other machines, each with its own keys. A witness checks that the checkpoint extends the
  last one it signed for this log, signs it too, and keeps a copy. It never signs two different
  checkpoints with the same number.
- Verification recomputes every root from the records as they are now, checks every signature,
  and asks each witness what it signed. A record changed after it was sealed changes the root.
  Resealing the changed records needs the node's key, and even with the key (an insider on the
  collector's machine) the witnesses' copies still show the original checkpoint: the rewrite is
  reported, with the checkpoint number where the histories part.

What this does not prove: that the device sent the truth, or that records written after the last
checkpoint are untouched (they are covered by the chain, and by the next checkpoint).
"""
import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.config import settings
from backend.services import jsonio
from backend.services.integrity import merkle, signing
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.storage import db as db_module

logger = logging.getLogger("tracelog.checkpoints")

GENESIS = "0" * 64
BODY_VERSION = 1


class RewriteActive(RuntimeError):
    """The history-rewrite demonstration is active: nothing is sealed until it is restored."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------- plumbing
def log_id(conn) -> str:
    row = conn.execute("SELECT value FROM tracelog_meta WHERE key = 'log_id'").fetchone()
    return row[0] if row else ""


def key_dir() -> Path:
    if settings.TRACELOG_KEY_DIR:
        return Path(settings.TRACELOG_KEY_DIR)
    return Path(db_module.db.db_path).resolve().parent / "keys"


_signers: Dict[str, signing.Signer] = {}
_signer_lock = threading.Lock()


def node_signer() -> signing.Signer:
    """This collector's keys (created on first use). Only the writer ever loads them."""
    path = str(key_dir())
    with _signer_lock:
        if path not in _signers:
            _signers[path] = signing.Signer("node", Path(path))
        return _signers[path]


def witness_urls() -> List[str]:
    return [u.strip().rstrip("/") for u in settings.WITNESS_URLS.split(",") if u.strip()]


def _http(method: str, url: str, **kwargs):
    """One HTTP call to a witness (tests replace this to talk to in-process witnesses)."""
    import requests
    return requests.request(method, url, timeout=kwargs.pop("timeout", 4.0), **kwargs)


def _rows(conn, sql: str, args=()) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _leaves(conn, first: int, last: int) -> List[bytes]:
    rows = conn.execute("SELECT sequence_num, record_hash FROM integrity_ledger WHERE sequence_num BETWEEN ? AND ? "
                        "ORDER BY sequence_num", (first, last)).fetchall()
    return [merkle.leaf_hash(merkle.leaf_data(r[0], r[1])) for r in rows]


def rewrite_active(conn) -> bool:
    return conn.execute("SELECT 1 FROM audit_rewrite_backup LIMIT 1").fetchone() is not None


# --------------------------------------------------------------------------------------- sealing
def _seal_range(conn, signer: signing.Signer, index: int, first: int, last: int, prev: str, log: str,
                sealed_at: Optional[str] = None) -> Dict[str, Any]:
    leaves = _leaves(conn, first, last)
    body = {"v": BODY_VERSION, "type": "tracelog-checkpoint", "log_id": log, "index": index,
            "first_seq": first, "last_seq": last, "size": len(leaves),
            "merkle_root": merkle.root(leaves).hex(), "prev_checkpoint": prev,
            "node_key_id": signer.key_id, "sealed_at": sealed_at or _now()}
    body_text = jsonio.canonical(body)
    sigs = [{"role": "node", "name": "node", "signed_at": body["sealed_at"], **s}
            for s in signer.sign(body_text.encode("utf-8"))]
    return {"idx": index, "log_id": log, "first_seq": first, "last_seq": last, "size": len(leaves),
            "merkle_root": body["merkle_root"], "prev_hash": prev, "checkpoint_hash": _sha(body_text),
            "body": body_text, "signatures": json.dumps(sigs), "created_at": body["sealed_at"]}


_INSERT = ("INSERT INTO checkpoints (idx, log_id, first_seq, last_seq, size, merkle_root, prev_hash, checkpoint_hash, "
           "body, signatures, created_at) VALUES (:idx, :log_id, :first_seq, :last_seq, :size, :merkle_root, "
           ":prev_hash, :checkpoint_hash, :body, :signatures, :created_at)")


def seal_in(conn, force: bool = False, size: Optional[int] = None) -> List[Dict[str, Any]]:
    """Seal what is due, inside the caller's transaction and write lock. Full windows of `size`
    records always; the last, partial window only when `force`. Returns the new checkpoints."""
    size = size or max(1, settings.CHECKPOINT_SIZE)
    if not signing.HAVE_CRYPTO:
        if force:
            raise RuntimeError("signing needs the 'cryptography' package: pip install -r requirements.txt")
        return []
    if rewrite_active(conn):
        if force:
            raise RewriteActive("the history-rewrite demonstration is active: restore the history first")
        return []
    last = conn.execute("SELECT idx, last_seq, checkpoint_hash FROM checkpoints ORDER BY idx DESC LIMIT 1").fetchone()
    index, sealed, prev = (last[0], last[1], last[2]) if last else (0, 0, GENESIS)
    head = conn.execute("SELECT MAX(sequence_num) FROM integrity_ledger").fetchone()[0] or 0
    if head <= sealed or (head - sealed < size and not force):
        return []
    signer, log, made = node_signer(), log_id(conn), []
    while head > sealed and (head - sealed >= size or force):
        first, end = sealed + 1, min(head, sealed + size)
        index += 1
        row = _seal_range(conn, signer, index, first, end, prev, log)
        conn.execute(_INSERT, row)
        made.append(row)
        sealed, prev = end, row["checkpoint_hash"]
    return made


def seal(force: bool = True) -> List[Dict[str, Any]]:
    """Seal everything not yet covered (force) or only full windows, in its own transaction."""
    with IntegrityLedger.write_lock, db_module.db.get_connection() as conn:
        made = seal_in(conn, force=force)
        conn.commit()
    return made


# --------------------------------------------------------------------------------------- witnesses
WITNESS_STATUS: Dict[str, Dict[str, Any]] = {}


def _signatures(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    return json.loads(row["signatures"] or "[]")


_signed_through: Dict[str, int] = {}   # per witness: every checkpoint up to here carries its signature


def _unsigned_by(url: str, limit: int) -> List[Dict[str, Any]]:
    """The oldest checkpoints without this witness's signature, in order, reading a page at a time."""
    with db_module.db.get_connection() as conn:
        cache = f"{db_module.db.db_path}|{log_id(conn)}|{url}"
        out, after = [], _signed_through.get(cache, 0)
        while len(out) < limit:
            page = _rows(conn, "SELECT * FROM checkpoints WHERE idx > ? ORDER BY idx LIMIT 500", (after,))
            if not page:
                break
            for row in page:
                if any(s.get("role") == "witness" and s.get("url") == url for s in _signatures(row)):
                    if not out:
                        _signed_through[cache] = row["idx"]
                else:
                    out.append(row)
            after = page[-1]["idx"]
    return out[:limit]


def cosign_pending(limit: int = 500) -> Dict[str, Dict[str, Any]]:
    """Send each witness the checkpoints it has not signed yet, oldest first, and keep its signatures."""
    report = {}
    for url in witness_urls():
        status = {"url": url, "reachable": False, "signed": 0, "error": None, "witness": None}
        try:
            info = _http("GET", f"{url}/witness/info").json()
            status.update(reachable=True, witness=info.get("witness"))
        except Exception as exc:
            status["error"] = f"not reachable: {exc.__class__.__name__}"
            report[url] = WITNESS_STATUS[url] = status
            continue
        for row in _unsigned_by(url, limit):
            node_sigs = [s for s in _signatures(row) if s.get("role") == "node"]
            try:
                r = _http("POST", f"{url}/witness/cosign", json={"body": row["body"], "signatures": node_sigs})
            except Exception as exc:
                status["error"] = f"stopped at checkpoint #{row['idx']}: {exc.__class__.__name__}"
                break
            if r.status_code != 200:
                try:
                    detail = r.json().get("detail")
                except Exception:
                    detail = r.text[:200]
                status["error"] = f"refused checkpoint #{row['idx']}: {detail}"
                status["refused"] = {"index": row["idx"], "detail": detail}
                break
            answer = r.json()
            new = [{"role": "witness", "name": answer.get("witness"), "url": url,
                    "signed_at": answer.get("signed_at"), **s} for s in answer.get("signatures", [])]
            with IntegrityLedger.write_lock, db_module.db.get_connection() as conn:
                current = conn.execute("SELECT signatures, checkpoint_hash FROM checkpoints WHERE idx = ?",
                                       (row["idx"],)).fetchone()
                if current is None or current[1] != row["checkpoint_hash"]:
                    break      # the checkpoint changed underneath (a rewrite demonstration): next round
                sigs = [s for s in json.loads(current[0]) if s.get("url") != url] + new
                conn.execute("UPDATE checkpoints SET signatures = ? WHERE idx = ?", (json.dumps(sigs), row["idx"]))
                conn.commit()
            status["signed"] += 1
        report[url] = WITNESS_STATUS[url] = status
    return report


# --------------------------------------------------------------------------------------- verification
def _check_signatures(sigs: List[Dict[str, Any]], message: bytes) -> List[str]:
    problems = []
    for s in sigs:
        ok = signing.verify(s.get("alg", ""), s.get("public_key", ""), message, s.get("sig", ""))
        if ok is False:
            who = "this node" if s.get("role") == "node" else f"witness {s.get('name') or s.get('url')}"
            problems.append(f"the {s.get('alg')} signature of {who} does not match the checkpoint")
    return problems


def _witness_view(url: str, log: str) -> Dict[str, Any]:
    """What a witness says it signed for this log: {index: checkpoint_hash}, its identity and the node key it pinned."""
    info = _http("GET", f"{url}/witness/info").json()
    signed: Dict[int, str] = {}
    after = 0
    while True:
        page = _http("GET", f"{url}/witness/logs/{log}/checkpoints", params={"after": after, "limit": 2000}).json()
        for item in page:
            signed[int(item["index"])] = item["checkpoint_hash"]
        if len(page) < 2000:
            break
        after = max(signed)
    pinned = next((l.get("node_key_id") for l in info.get("logs", []) if l.get("log_id") == log), None)
    return {"witness": info.get("witness"), "signed": signed, "node_key_id": pinned,
            "public_keys": info.get("public_keys", [])}


def verify(ask_witnesses: bool = True) -> Dict[str, Any]:
    """Recompute every checkpoint from the records as they are now, check every signature, and compare
    with what each witness signed."""
    with db_module.db.get_connection() as conn:
        rows = _rows(conn, "SELECT * FROM checkpoints ORDER BY idx")
        head = conn.execute("SELECT MAX(sequence_num) FROM integrity_ledger").fetchone()[0] or 0
        log = log_id(conn)
        active = rewrite_active(conn)
        problems: List[Dict[str, Any]] = []
        prev, expected_first, node_keys = GENESIS, None, set()
        for row in rows:
            idx, text = row["idx"], row["body"]
            try:
                body = json.loads(text)
            except ValueError:
                problems.append({"index": idx, "problem": "the checkpoint's signed text is not readable"})
                continue
            if _sha(text) != row["checkpoint_hash"]:
                problems.append({"index": idx, "problem": "the checkpoint's hash does not match its signed text"})
            if (body.get("index"), body.get("first_seq"), body.get("last_seq"), body.get("merkle_root")) != \
                    (idx, row["first_seq"], row["last_seq"], row["merkle_root"]):
                problems.append({"index": idx, "problem": "the stored columns differ from the signed text"})
            if body.get("prev_checkpoint") != prev:
                problems.append({"index": idx, "problem": f"it does not follow checkpoint #{idx - 1}"})
            if expected_first is not None and body.get("first_seq") != expected_first:
                problems.append({"index": idx, "problem": f"records #{expected_first} to #{body.get('first_seq', 0) - 1}"
                                                          f" are in no checkpoint"})
            leaves = _leaves(conn, body.get("first_seq", 0), body.get("last_seq", -1))
            if len(leaves) != body.get("size"):
                problems.append({"index": idx, "problem": f"it covers {body.get('size')} records; "
                                                          f"{len(leaves)} are stored now"})
            elif merkle.root(leaves).hex() != body.get("merkle_root"):
                problems.append({"index": idx, "problem": "records it covers were changed after it was signed "
                                                          "(the Merkle root no longer matches)"})
            sigs = _signatures(row)
            node_sigs = [s for s in sigs if s.get("role") == "node"]
            if not node_sigs:
                problems.append({"index": idx, "problem": "it carries no signature of this node"})
            node_keys |= {s["key_id"] for s in node_sigs if s.get("alg") == signing.ED25519}
            if any(s.get("alg") == signing.ED25519 and s.get("key_id") != body.get("node_key_id") for s in node_sigs):
                problems.append({"index": idx, "problem": "it is signed with a key other than the one it names"})
            for p in _check_signatures(sigs, text.encode("utf-8")):
                problems.append({"index": idx, "problem": p})
            prev, expected_first = row["checkpoint_hash"], body.get("last_seq", 0) + 1
    if rows and len(node_keys) > 1:
        problems.append({"index": None, "problem": f"checkpoints are signed by {len(node_keys)} different node keys"})

    sealed = rows[-1]["last_seq"] if rows else 0
    by_idx = {r["idx"]: r for r in rows}
    witnesses = []
    if ask_witnesses:
        for url in witness_urls():
            w = {"url": url, "reachable": False, "witness": None, "agree": 0, "pending": 0, "differ": [],
                 "missing_here": [], "node_key_matches": None}
            try:
                view = _witness_view(url, log)
            except Exception as exc:
                w["error"] = f"not reachable: {exc.__class__.__name__}"
                witnesses.append(w)
                continue
            w.update(reachable=True, witness=view["witness"])
            if view["node_key_id"]:
                w["node_key_matches"] = not node_keys or node_keys == {view["node_key_id"]}
                if not w["node_key_matches"]:
                    problems.append({"index": None, "problem": f"witness {view['witness']} knows this log by a "
                                                               f"different node key"})
            for idx, row in by_idx.items():
                theirs = view["signed"].get(idx)
                if theirs is None:
                    w["pending"] += 1
                elif theirs == row["checkpoint_hash"]:
                    w["agree"] += 1
                else:
                    w["differ"].append(idx)
            w["missing_here"] = sorted(i for i in view["signed"] if i not in by_idx)
            if w["differ"]:
                problems.append({"index": w["differ"][0],
                                 "problem": f"witness {view['witness']} signed a different checkpoint "
                                            f"#{w['differ'][0]}: the history was rewritten after it was witnessed"})
            if w["missing_here"]:
                problems.append({"index": w["missing_here"][0],
                                 "problem": f"witness {view['witness']} signed checkpoints this archive no longer "
                                            f"has (#{w['missing_here'][0]} onwards)"})
            witnesses.append(w)

    last = rows[-5:]
    return {
        "ok": not problems, "checked_at": _now(), "log_id": log,
        "checkpoints": len(rows), "sealed_records": sealed, "head_seq": head,
        "unsealed_records": max(0, head - sealed), "rewrite_demo_active": active,
        "node_key_id": next(iter(node_keys)) if len(node_keys) == 1 else None,
        "algorithms": sorted({s.get("alg") for r in rows for s in _signatures(r)}),
        "problems": problems, "witnesses": witnesses, "witnesses_configured": len(witness_urls()),
        "latest": [{"index": r["idx"], "first_seq": r["first_seq"], "last_seq": r["last_seq"], "size": r["size"],
                    "merkle_root": r["merkle_root"], "checkpoint_hash": r["checkpoint_hash"],
                    "sealed_at": r["created_at"],
                    "signers": sorted({s.get("name") or s.get("role") for s in _signatures(r)})}
                   for r in reversed(last)],
    }


# --------------------------------------------------------------------------------------- proofs
def proof(sequence_num: int, conn=None) -> Optional[Dict[str, Any]]:
    """The inclusion proof of one chain record in the checkpoint that covers it, or None if unsealed."""
    def build(c):
        row = c.execute("SELECT * FROM checkpoints WHERE first_seq <= ? AND last_seq >= ? ORDER BY idx LIMIT 1",
                        (sequence_num, sequence_num)).fetchone()
        rec = c.execute("SELECT record_hash FROM integrity_ledger WHERE sequence_num = ?", (sequence_num,)).fetchone()
        if row is None or rec is None:
            return None
        row = dict(row)
        seqs = [r[0] for r in c.execute("SELECT sequence_num FROM integrity_ledger WHERE sequence_num BETWEEN ? AND ? "
                                         "ORDER BY sequence_num", (row["first_seq"], row["last_seq"])).fetchall()]
        leaves = _leaves(c, row["first_seq"], row["last_seq"])
        index = seqs.index(sequence_num)
        return {"sequence_num": sequence_num, "record_hash": rec[0],
                "leaf": merkle.leaf_data(sequence_num, rec[0]).decode(), "leaf_index": index,
                "tree_size": len(leaves), "path": [h.hex() for h in merkle.inclusion_path(index, leaves)],
                "checkpoint": {"index": row["idx"], "body": row["body"], "checkpoint_hash": row["checkpoint_hash"],
                               "signatures": _signatures(row)}}
    if conn is not None:
        return build(conn)
    with db_module.db.get_connection() as c:
        return build(c)


# --------------------------------------------------------------------------------------- demonstration
def rewrite_history(sequence_num: int, field: str = "disposition", value: str = "allowed") -> Dict[str, Any]:
    """What an insider with the database and the node's keys could do: change one stored event,
    recompute every record hash after it so the chain is consistent again, and reseal and re-sign
    the checkpoints from there on. Only the witnesses' copies still show the original.
    For demonstrations only; restore_history() puts everything back."""
    with IntegrityLedger.write_lock, db_module.db.get_connection() as conn:
        if rewrite_active(conn):
            raise ValueError("a rewrite is already active: restore the history first")
        ev = conn.execute("SELECT id, normalized_json FROM normalized_events WHERE sequence_num = ?",
                          (sequence_num,)).fetchone()
        if ev is None:
            raise ValueError(f"no record #{sequence_num}")
        head = conn.execute("SELECT MAX(sequence_num) FROM integrity_ledger").fetchone()[0]
        ledger = _rows(conn, "SELECT sequence_num, raw_hash, record_hash, prev_hash FROM integrity_ledger "
                             "WHERE sequence_num >= ? ORDER BY sequence_num", (sequence_num,))
        cps = _rows(conn, "SELECT * FROM checkpoints WHERE last_seq >= ? ORDER BY idx", (sequence_num,))
        data = jsonio.loads(ev["normalized_json"])
        original = str(data.get(field, ""))
        if original == value:
            raise ValueError(f"record #{sequence_num} already has {field} = {value!r}: choose another value")
        data[field] = value
        changed = jsonio.canonical(data)
        conn.execute("UPDATE normalized_events SET normalized_json = ?" + (", disposition = ?" if field == "disposition"
                     else "") + " WHERE sequence_num = ?",
                     (changed, value, sequence_num) if field == "disposition" else (changed, sequence_num))
        texts = {r[0]: r[1] for r in conn.execute("SELECT sequence_num, normalized_json FROM normalized_events "
                                                  "WHERE sequence_num >= ?", (sequence_num,)).fetchall()}
        prev = ledger[0]["prev_hash"]
        for rec in ledger:
            new_hash = IntegrityLedger.link(rec["sequence_num"], prev, rec["raw_hash"], texts[rec["sequence_num"]])
            conn.execute("UPDATE integrity_ledger SET prev_hash = ?, record_hash = ? WHERE sequence_num = ?",
                         (prev, new_hash, rec["sequence_num"]))
            prev = new_hash
        resealed = 0
        if cps:
            signer, log = node_signer(), log_id(conn)
            prev_cp = conn.execute("SELECT checkpoint_hash FROM checkpoints WHERE idx = ?",
                                   (cps[0]["idx"] - 1,)).fetchone()
            prev_cp = prev_cp[0] if prev_cp else GENESIS
            conn.execute("DELETE FROM checkpoints WHERE idx >= ?", (cps[0]["idx"],))
            for cp in cps:
                row = _seal_range(conn, signer, cp["idx"], cp["first_seq"], cp["last_seq"], prev_cp, log,
                                  sealed_at=cp["created_at"])   # a careful insider keeps the times
                conn.execute(_INSERT, row)
                prev_cp = row["checkpoint_hash"]
                resealed += 1
        backup = {"field": field, "original_json": ev["normalized_json"], "head": head, "ledger": ledger,
                  "checkpoints": cps}
        conn.execute("INSERT INTO audit_rewrite_backup (sequence_num, data_json, created_at) VALUES (?, ?, ?)",
                     (sequence_num, json.dumps(backup), _now()))
        conn.commit()
    _signed_through.clear()
    return {"success": True, "sequence_num": sequence_num, "field": field, "original_value": original,
            "new_value": value, "records_rehashed": len(ledger), "checkpoints_resigned": resealed}


def restore_history() -> Dict[str, Any]:
    """Undo rewrite_history(): the event, every record hash and every checkpoint as they were."""
    with IntegrityLedger.write_lock, db_module.db.get_connection() as conn:
        row = conn.execute("SELECT sequence_num, data_json FROM audit_rewrite_backup ORDER BY id LIMIT 1").fetchone()
        if row is None:
            raise ValueError("no rewrite to restore")
        seq, backup = row[0], json.loads(row[1])
        original = backup["original_json"]
        disposition = jsonio.loads(original).get("disposition")
        conn.execute("UPDATE normalized_events SET normalized_json = ?, disposition = ? WHERE sequence_num = ?",
                     (original, disposition, seq))
        for rec in backup["ledger"]:
            conn.execute("UPDATE integrity_ledger SET prev_hash = ?, record_hash = ? WHERE sequence_num = ?",
                         (rec["prev_hash"], rec["record_hash"], rec["sequence_num"]))
        # records chained while the rewrite was active linked to the rewritten head: link them again
        later = _rows(conn, "SELECT l.sequence_num, l.raw_hash, n.normalized_json FROM integrity_ledger l "
                            "JOIN normalized_events n ON n.id = l.event_id WHERE l.sequence_num > ? "
                            "ORDER BY l.sequence_num", (backup["head"],))
        prev = backup["ledger"][-1]["record_hash"] if backup["ledger"] else GENESIS
        for rec in later:
            new_hash = IntegrityLedger.link(rec["sequence_num"], prev, rec["raw_hash"], rec["normalized_json"])
            conn.execute("UPDATE integrity_ledger SET prev_hash = ?, record_hash = ? WHERE sequence_num = ?",
                         (prev, new_hash, rec["sequence_num"]))
            prev = new_hash
        if backup["checkpoints"]:
            conn.execute("DELETE FROM checkpoints WHERE idx >= ?", (backup["checkpoints"][0]["idx"],))
            for cp in backup["checkpoints"]:
                conn.execute(_INSERT, cp)
        conn.execute("DELETE FROM audit_rewrite_backup")
        conn.commit()
    _signed_through.clear()
    for status in WITNESS_STATUS.values():
        status.pop("refused", None)
        status["error"] = None
    return {"success": True, "sequence_num": seq, "records_relinked": len(later)}


def reset_log(conn) -> None:
    """A reset archive is a new log for the witnesses (they keep what they signed for the old one)."""
    import uuid
    conn.execute("DELETE FROM checkpoints")
    conn.execute("DELETE FROM audit_rewrite_backup")
    conn.execute("INSERT OR REPLACE INTO tracelog_meta (key, value) VALUES ('log_id', ?)", (str(uuid.uuid4()),))
    _signed_through.clear()


# --------------------------------------------------------------------------------------- the timer
class Schedule:
    """In the collector: every `seconds`, seal what is not yet sealed and send it to the witnesses."""

    def __init__(self, seconds: int, tick: Optional[Callable[[], None]] = None):
        self.seconds = seconds
        self._stop = threading.Event()
        self._tick = tick or self.tick
        self._thread = threading.Thread(target=self._run, name="checkpoints", daemon=True)

    @staticmethod
    def tick() -> None:
        try:
            seal(force=True)
        except RewriteActive:
            pass
        except Exception:
            logger.exception("sealing failed")
        try:
            cosign_pending()
        except Exception:
            logger.exception("witness round failed")

    def _run(self) -> None:
        while not self._stop.wait(self.seconds):
            self._tick()

    def start(self) -> "Schedule":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
