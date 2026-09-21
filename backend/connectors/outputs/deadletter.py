"""
Dead-letter store for one output: events TRACELOG could not deliver, kept on disk
as one JSON line each, and re-sent later.

    data/dead_letter/<output>.ndjson             waiting to be re-sent
    data/dead_letter/<output>.replaying.ndjson   claimed by a replay that is running (or was cut off)
    data/dead_letter/<output>.replaying.offset   bytes of the claimed file already delivered

Each line:
    {"kind": "undeliverable" | "rejected" | "queue_full", "reason": "...", "at": "<ISO time>",
     "attempts": 6, "source": "Palo Alto Networks PAN-OS (PA-3220)", "output": "splunk", "event": {OCSF}}

kinds:
    undeliverable  every retry failed (destination down, timeout, HTTP 408/429/5xx). Safe to re-send as is.
    queue_full     the output's queue overflowed during a burst. Safe to re-send as is.
    rejected       the destination refused the event (HTTP 4xx, mapping or validation error). Re-sending
                   only helps once the cause is fixed (token, index mapping, payload size).

A replay claims the waiting file by renaming it, so new dead letters keep landing
in a fresh file while it runs. After each batch the destination accepts, the
delivered position is saved. If the destination fails, a limit is reached or
TRACELOG stops, the claimed file stays with its position and the next replay
continues from there, so at most one batch is ever sent twice. Entries skipped
(other kinds) or refused again go back to the waiting file. Nothing is deleted
until it has been delivered.
"""
import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

KINDS = ("undeliverable", "queue_full", "rejected")
AUTO_KINDS = ("undeliverable", "queue_full")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def entry(event: Dict[str, Any], kind: str, reason: str, attempts: int, source: str = "",
          output: str = "") -> Dict[str, Any]:
    return {"kind": kind, "reason": reason[:500], "at": now_iso(), "attempts": attempts, "source": source,
            "output": output, "event": event}


def _normalise(e: Dict[str, Any]) -> Dict[str, Any]:
    """Entries written before kinds existed: {"reason", "at", "event"}."""
    if "kind" not in e:
        reason = str(e.get("reason", ""))
        e["kind"] = "queue_full" if reason == "queue full" else "undeliverable"
    e.setdefault("attempts", 1)
    e.setdefault("source", "")
    return e


class DeadLetterStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.name = self.path.stem
        self.claim_path = self.path.with_name(f"{self.name}.replaying.ndjson")
        self.offset_path = self.path.with_name(f"{self.name}.replaying.offset")
        self.lock = threading.RLock()
        self.busy = False  # a replay is running
        self._summary_cache: Tuple[Any, Optional[Dict[str, Any]]] = (None, None)

    # ---- writing --------------------------------------------------------------------------
    def append(self, entries: List[Dict[str, Any]]) -> None:
        if not entries:
            return
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for e in entries:
                    fh.write(json.dumps(e, default=str, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    # ---- reading --------------------------------------------------------------------------
    def _files(self) -> List[Tuple[Path, int]]:
        """(file, start offset) pairs holding entries that have not been delivered yet."""
        out = []
        if self.claim_path.exists():
            out.append((self.claim_path, self._read_offset()))
        if self.path.exists():
            out.append((self.path, 0))
        return out

    def iter_entries(self) -> Iterator[Dict[str, Any]]:
        for path, start in self._files():
            with path.open("rb") as fh:
                fh.seek(start)
                for raw in fh:
                    if raw.strip():
                        try:
                            yield _normalise(json.loads(raw))
                        except ValueError:
                            continue

    def summary(self) -> Dict[str, Any]:
        key = tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns, off) for p, off in self._files())
        if self._summary_cache[0] == key and self._summary_cache[1] is not None:
            return {**self._summary_cache[1], "replay_running": self.busy}
        kinds: Counter = Counter()
        reasons: Counter = Counter()
        sources: Counter = Counter()
        oldest = newest = None
        for e in self.iter_entries():
            kinds[e["kind"]] += 1
            reasons[e.get("reason", "")[:160]] += 1
            if e.get("source"):
                sources[e["source"]] += 1
            at = e.get("at")
            if at:
                oldest = at if oldest is None or at < oldest else oldest
                newest = at if newest is None or at > newest else newest
        s = {"output": self.name, "file": str(self.path), "waiting": sum(kinds.values()),
             "by_kind": {k: kinds.get(k, 0) for k in KINDS},
             "auto_resendable": sum(kinds.get(k, 0) for k in AUTO_KINDS),
             "top_reasons": [{"reason": r, "count": n} for r, n in reasons.most_common(5)],
             "by_source": dict(sources.most_common(10)), "oldest": oldest, "newest": newest}
        self._summary_cache = (key, s)
        return {**s, "replay_running": self.busy}

    def latest(self, limit: int = 20) -> List[Dict[str, Any]]:
        items = list(self.iter_entries())
        return list(reversed(items[-limit:]))

    def waiting(self, kinds: Tuple[str, ...] = KINDS) -> int:
        s = self.summary()
        return sum(s["by_kind"].get(k, 0) for k in kinds)

    # ---- replay ---------------------------------------------------------------------------
    def _read_offset(self) -> int:
        try:
            return int(self.offset_path.read_text().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _write_offset(self, n: int) -> None:
        tmp = self.offset_path.with_suffix(".tmp")
        tmp.write_text(str(n))
        os.replace(tmp, self.offset_path)

    def _claim(self) -> Optional[Path]:
        """Take the waiting file (renamed, so new dead letters start a fresh one)."""
        with self.lock:
            if self.path.exists() and self.path.stat().st_size > 0:
                os.replace(self.path, self.claim_path)
                self._write_offset(0)
                return self.claim_path
        return None

    def _finish(self) -> None:
        """The claimed file has been worked through: drop it."""
        with self.lock:
            for path in (self.claim_path, self.offset_path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def replay(self, send: Callable[[List[Dict[str, Any]]], Tuple[int, List[Dict[str, Any]]]],
               batch_size: int = 200, kinds: Tuple[str, ...] = KINDS, limit: Optional[int] = None,
               progress: Optional[Dict[str, Any]] = None, should_stop: Callable[[], bool] = lambda: False
               ) -> Dict[str, Any]:
        """
        Re-send waiting entries through `send(entries) -> (delivered, refused_entries)`. If `send`
        raises, the destination is not accepting events: the replay stops and the batch stays where
        it was, to be tried again next time.
        """
        p = progress if progress is not None else {}
        p.update({"state": "running", "delivered": 0, "refused_again": 0, "skipped_other_kinds": 0,
                  "error": None, "started_at": now_iso(), "finished_at": None})
        with self.lock:
            if self.busy:
                p.update({"state": "busy", "error": "a replay of these dead letters is already running"})
                return p
            self.busy = True
        try:
            claimed_waiting_file = False
            while True:
                if self.claim_path.exists():            # resume a replay that was cut off or limited
                    claim = self.claim_path
                elif not claimed_waiting_file:           # then take the waiting file, once per run
                    claim = self._claim()
                    claimed_waiting_file = True
                else:
                    claim = None
                if claim is None:
                    p["state"] = "done"
                    break
                if self._replay_file(claim, send, batch_size, kinds, limit, p, should_stop):
                    break
        finally:
            with self.lock:
                self.busy = False
            p["finished_at"] = now_iso()
        return p

    def _replay_file(self, claim: Path, send, batch_size, kinds, limit, p, should_stop) -> bool:
        """Work through the claimed file from the saved offset. Returns True if the run stopped early;
        the claim then stays in place with its offset, and the next replay continues from there."""
        with claim.open("rb") as fh:
            fh.seek(self._read_offset())
            while True:
                budget = batch_size if limit is None else min(batch_size, limit - p["delivered"])
                if budget <= 0:
                    p["state"] = "limit_reached"
                    return True
                if should_stop():
                    p["state"], p["error"] = "stopped", p["error"] or "TRACELOG is shutting down"
                    return True
                batch, keep, eof = [], [], False
                while len(batch) < budget:
                    raw = fh.readline()
                    if not raw:
                        eof = True
                        break
                    try:
                        e = _normalise(json.loads(raw)) if raw.strip() else None
                    except ValueError:
                        e = None
                    if e is not None:
                        (batch if e["kind"] in kinds else keep).append(e)
                refused: List[Dict[str, Any]] = []
                if batch:
                    try:
                        delivered, refused = send(batch)
                    except Exception as exc:  # nothing accepted: leave this batch in place for next time
                        p["error"] = f"{type(exc).__name__}: {exc}"[:500]
                        p["state"] = "stopped"
                        return True
                    p["delivered"] += delivered
                    p["refused_again"] += len(refused)
                p["skipped_other_kinds"] += len(keep)
                # settle the chunk: park entries not re-sent now, then record the position.
                # A crash between the two can duplicate a parked entry, never lose one.
                self.append(keep + refused)
                self._write_offset(fh.tell())
                if eof:
                    self._finish()
                    return False
