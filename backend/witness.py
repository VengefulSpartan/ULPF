"""
A witness: a small separate service that countersigns TRACELOG checkpoints and remembers them.

Run one or more, ideally on machines the collector's administrators do not control:

    WITNESS_ID=witness-1 WITNESS_DATA_DIR=/var/lib/tracelog-witness uvicorn backend.witness:app --port 8101

and list them in the collector's WITNESS_URLS. A witness needs no database of logs and sees no
log lines: only checkpoint bodies (a range of sequence numbers, a Merkle root, the previous
checkpoint's hash and the node's key id).

It signs checkpoint N of a log only if
- the body carries a valid signature by the node key this witness first saw for that log
  (trust on first use; the key is pinned from then on);
- N is the next number: it has signed 1 to N-1 of this log and nothing numbered N;
- the body names, as its previous checkpoint, the hash of the N-1 this witness signed.

So a witness never signs two different checkpoints with one number, and never signs a history
that does not extend the one it already signed. Asked to, it refuses with 409 and says why:
that refusal is how a rewritten history is caught. Everything it signed stays in its own SQLite
file, which verification reads back (GET /witness/logs/{log_id}/checkpoints).
"""
import base64
import hashlib
import json
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from backend.config import settings
from backend.services.integrity import signing

GENESIS = "0" * 64


class CosignRequest(BaseModel):
    body: str
    signatures: List[Dict[str, Any]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Witness:
    def __init__(self, name: str, directory: Path):
        self.name = name
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.signer = signing.Signer("witness", self.directory / "keys")
        self.path = self.directory / "witness.db"
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS nodes (log_id TEXT PRIMARY KEY, node_key_id TEXT NOT NULL, "
                      "node_keys TEXT NOT NULL, first_seen TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS cosigned (log_id TEXT NOT NULL, idx INTEGER NOT NULL, "
                      "checkpoint_hash TEXT NOT NULL, body TEXT NOT NULL, signatures TEXT NOT NULL, "
                      "signed_at TEXT NOT NULL, PRIMARY KEY (log_id, idx))")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------ the one thing a witness does
    def cosign(self, body_text: str, node_signatures: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            body = json.loads(body_text)
            log, index, prev = body["log_id"], int(body["index"]), body["prev_checkpoint"]
            node_key = body["node_key_id"]
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "not a TRACELOG checkpoint body")
        message = body_text.encode("utf-8")
        ed = [s for s in node_signatures if s.get("alg") == signing.ED25519]
        if not ed or ed[0].get("key_id") != node_key:
            raise HTTPException(400, "the checkpoint carries no Ed25519 signature by the key it names")
        for s in node_signatures:
            try:
                named = signing.key_id(base64.b64decode(s.get("public_key", ""), validate=True)) == s.get("key_id")
            except ValueError:
                named = False
            if not named:
                raise HTTPException(400, "a signature's public key does not match its key id")
            if signing.verify(s.get("alg", ""), s.get("public_key", ""), message, s.get("sig", "")) is False:
                raise HTTPException(400, f"the node's {s.get('alg')} signature does not match the checkpoint")
        digest = hashlib.sha256(message).hexdigest()

        with self._lock, self._conn() as c:
            pinned = c.execute("SELECT node_key_id FROM nodes WHERE log_id = ?", (log,)).fetchone()
            if pinned is None:
                c.execute("INSERT INTO nodes (log_id, node_key_id, node_keys, first_seen) VALUES (?, ?, ?, ?)",
                          (log, node_key, json.dumps([{k: s[k] for k in ("alg", "key_id", "public_key")}
                                                      for s in node_signatures]), _now()))
            elif pinned[0] != node_key:
                raise HTTPException(409, f"this log was first signed by node key {pinned[0]}, not {node_key}")
            same = c.execute("SELECT checkpoint_hash, signatures, signed_at FROM cosigned WHERE log_id = ? AND idx = ?",
                             (log, index)).fetchone()
            if same is not None:
                if same[0] != digest:
                    raise HTTPException(409, f"checkpoint #{index} of this log was already signed with hash "
                                             f"{same[0][:16]}…; refusing a different one ({digest[:16]}…)")
                return {"witness": self.name, "signatures": json.loads(same[1]), "signed_at": same[2]}
            last = c.execute("SELECT idx, checkpoint_hash FROM cosigned WHERE log_id = ? ORDER BY idx DESC LIMIT 1",
                             (log,)).fetchone()
            last_idx, last_hash = (last[0], last[1]) if last else (0, GENESIS)
            if index != last_idx + 1:
                raise HTTPException(409, f"expected checkpoint #{last_idx + 1} of this log next, got #{index}")
            if prev != last_hash:
                raise HTTPException(409, f"checkpoint #{index} does not extend checkpoint #{last_idx} as this "
                                         f"witness signed it")
            sigs = self.signer.sign(message)
            at = _now()
            c.execute("INSERT INTO cosigned (log_id, idx, checkpoint_hash, body, signatures, signed_at) "
                      "VALUES (?, ?, ?, ?, ?, ?)", (log, index, digest, body_text, json.dumps(sigs), at))
            c.commit()
        return {"witness": self.name, "signatures": sigs, "signed_at": at}

    # ------------------------------------------------------------------ what it can tell
    def info(self) -> Dict[str, Any]:
        with self._conn() as c:
            logs = [{"log_id": r[0], "node_key_id": r[1], "first_seen": r[2],
                     "checkpoints": r[3] or 0, "last_index": r[4] or 0}
                    for r in c.execute("SELECT n.log_id, n.node_key_id, n.first_seen, COUNT(s.idx), MAX(s.idx) "
                                       "FROM nodes n LEFT JOIN cosigned s ON s.log_id = n.log_id GROUP BY n.log_id")]
        return {"witness": self.name, "host": socket.gethostname(), "algorithms": signing.algorithms(),
                "public_keys": self.signer.public_keys(), "logs": logs}

    def signed(self, log: str, after: int, limit: int) -> List[Dict[str, Any]]:
        with self._conn() as c:
            return [{"index": r[0], "checkpoint_hash": r[1], "signed_at": r[2]}
                    for r in c.execute("SELECT idx, checkpoint_hash, signed_at FROM cosigned WHERE log_id = ? AND "
                                       "idx > ? ORDER BY idx LIMIT ?", (log, after, limit))]

    def one(self, log: str, index: int) -> Dict[str, Any]:
        with self._conn() as c:
            r = c.execute("SELECT idx, checkpoint_hash, body, signatures, signed_at FROM cosigned WHERE log_id = ? "
                          "AND idx = ?", (log, index)).fetchone()
        if r is None:
            raise HTTPException(404, f"this witness has not signed checkpoint #{index} of that log")
        return {"index": r[0], "checkpoint_hash": r[1], "body": r[2], "signatures": json.loads(r[3]),
                "signed_at": r[4], "witness": self.name}


def create_app(name: str, directory: Path) -> FastAPI:
    witness = Witness(name, directory)
    application = FastAPI(title=f"TRACELOG witness {name}", docs_url=None, redoc_url=None)
    application.state.witness = witness

    @application.post("/witness/cosign")
    def cosign(req: CosignRequest):
        return witness.cosign(req.body, req.signatures)

    @application.get("/witness/info")
    def info():
        return witness.info()

    @application.get("/witness/logs/{log_id}/checkpoints")
    def signed(log_id: str, after: int = Query(0, ge=0), limit: int = Query(1000, ge=1, le=5000)):
        return witness.signed(log_id, after, limit)

    @application.get("/witness/logs/{log_id}/checkpoints/{index}")
    def one(log_id: str, index: int):
        return witness.one(log_id, index)

    @application.get("/health")
    def health():
        return {"status": "healthy", "service": f"TRACELOG witness {name}", "role": "witness"}

    return application


def _default_dir() -> Path:
    return Path(settings.WITNESS_DATA_DIR) if settings.WITNESS_DATA_DIR else settings.DATA_DIR / settings.WITNESS_ID


_app = None


def __getattr__(name: str):
    """`app` is built when uvicorn asks for it (backend.witness:app), not whenever this module is imported,
    so importing create_app (the tests) creates no key or database."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app(settings.WITNESS_ID, _default_dir())
        return _app
    raise AttributeError(name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.witness:app", host="127.0.0.1", port=8101)
