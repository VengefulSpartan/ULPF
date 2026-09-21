"""
Output connector base: each sink runs in its own thread with a bounded queue,
batches events, retries with exponential backoff, and writes anything it
cannot deliver to its dead-letter store instead of dropping it.

Dead letters are re-sent by the same thread that delivers live events, between
batches, so a destination is never written to from two threads at once:
- on request (API / dashboard), to this output or on behalf of another output;
- automatically, for undeliverable and queue_full entries, once the destination
  accepts events again (checked with backoff while it is still down).
"""
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.connectors.config import Output

from .deadletter import AUTO_KINDS, KINDS, DeadLetterStore, entry, now_iso

logger = logging.getLogger("tracelog.outputs")

Item = Tuple[Dict[str, Any], str]  # (OCSF event, source name)


class DeliveryError(Exception):
    """Raised by send(); `retryable=False` sends the batch straight to the dead-letter store."""

    def __init__(self, message: str, retryable: bool = True, rejected: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.retryable = retryable
        self.rejected = rejected  # subset of the batch that was permanently refused


class ReplayJob:
    def __init__(self, store: DeadLetterStore, kinds: Tuple[str, ...], limit: Optional[int], trigger: str):
        self.store, self.kinds, self.limit, self.trigger = store, kinds, limit, trigger
        self.progress: Dict[str, Any] = {"state": "queued", "source": store.name, "kinds": list(kinds),
                                         "limit": limit, "trigger": trigger}
        self.done = threading.Event()


class Sink(threading.Thread):
    type_name = "base"
    description = ""

    def __init__(self, cfg: Output, data_dir: str = "data", store: Optional[DeadLetterStore] = None):
        super().__init__(name=f"sink-{cfg.name}", daemon=True)
        self.cfg = cfg
        self.s = cfg.settings
        self.queue: "queue.Queue[Item]" = queue.Queue(maxsize=cfg.queue_size)
        self.store = store or DeadLetterStore(Path(data_dir) / "dead_letter" / f"{cfg.name}.ndjson")
        self.dlq_path = self.store.path
        self._jobs: "queue.Queue[ReplayJob]" = queue.Queue()
        self._stop_event = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._auto_backoff = cfg.auto_replay_interval_seconds
        self._next_auto_at = time.monotonic() + cfg.auto_replay_interval_seconds
        self.metrics: Dict[str, Any] = {"sent": 0, "failed": 0, "dead_lettered": 0, "retries": 0, "resent": 0,
                                        "last_error": None, "last_error_at": None, "last_success_at": None}
        self.last_replay: Optional[Dict[str, Any]] = None
        self.ledger = None      # DeliveryLedger when running inside the engine; None in unit use
        self.in_flight = 0      # events taken off the queue and being delivered right now
        self._replay_ctx: Tuple[str, str] = ("manual", cfg.name)  # (trigger, owning output) during a replay
        self.validate_settings()

    # ---- to implement in subclasses -------------------------------------------------------
    def validate_settings(self) -> None:
        """Raise ValueError for missing required settings."""

    def send(self, batch: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Release sockets/clients."""

    def describe_target(self) -> str:
        return self.s.get("url") or f"{self.s.get('host', '')}:{self.s.get('port', '')}"

    # ---- routing --------------------------------------------------------------------------
    def accepts(self, ocsf: Dict[str, Any], source_name: str) -> bool:
        f = self.cfg.filter
        if f.classes and ocsf.get("class_uid") not in f.classes:
            return False
        if (ocsf.get("severity_id") or 0) < f.min_severity_id:
            return False
        if f.sources and source_name not in f.sources:
            return False
        return True

    def put(self, ocsf: Dict[str, Any], source: str = "") -> None:
        if not self.cfg.include_raw and "raw_data" in ocsf:
            ocsf = {k: v for k, v in ocsf.items() if k != "raw_data"}
        try:
            self.queue.put_nowait((ocsf, source))
            self._idle.clear()
        except queue.Full:
            self._dead_letter([(ocsf, source)], "the output's queue was full", "queue_full", 0)

    def put_blocking(self, ocsf: Dict[str, Any], source: str = "", timeout: float = 60.0) -> bool:
        """For recovery after a restart: wait for queue space instead of dead-lettering."""
        try:
            self.queue.put((ocsf, source), timeout=timeout)
            self._idle.clear()
            return True
        except queue.Full:
            return False

    # ---- worker loop ----------------------------------------------------------------------
    def run(self) -> None:
        while not self._stop_event.is_set() or not self.queue.empty():
            self._run_jobs()
            self._maybe_auto_replay()
            items = self._take_batch()
            if not items:
                self._idle.set()
                continue
            self._deliver(items)
            if self.queue.empty():
                self._idle.set()
        self._run_jobs()  # answer anyone waiting; replays see should_stop() and return at once
        self.close()

    def _take_batch(self) -> List[Item]:
        batch: List[Item] = []
        deadline = time.monotonic() + self.cfg.flush_seconds
        while len(batch) < self.cfg.batch_size:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            try:
                batch.append(self.queue.get(timeout=min(timeout, 0.25)))
            except queue.Empty:
                if batch or self._stop_event.is_set() or not self._jobs.empty():
                    break
        return batch

    def _deliver(self, items: List[Item]) -> None:
        self.in_flight = len(items)
        try:
            self._deliver_items(items)
        finally:
            self.in_flight = 0

    def _deliver_items(self, items: List[Item]) -> None:
        batch = [e for e, _ in items]
        delay = self.cfg.retry_backoff_seconds
        attempts = 0
        for attempt in range(self.cfg.max_retries + 1):
            attempts = attempt + 1
            try:
                self.send(batch)
                self._delivered(len(batch))
                self._ledger(self.cfg.name, "delivered", "live", batch)
                return
            except DeliveryError as exc:
                self._record_error(exc)
                if exc.rejected:
                    refused = {id(e) for e in exc.rejected}
                    self._dead_letter([it for it in items if id(it[0]) in refused], str(exc), "rejected", attempts)
                    self._delivered(len(items) - len(refused))
                    self._ledger(self.cfg.name, "delivered", "live", [e for e in batch if id(e) not in refused])
                    return
                if not exc.retryable:
                    self.metrics["failed"] += len(items)
                    self._dead_letter(items, str(exc), "rejected", attempts)
                    return
            except Exception as exc:  # network errors etc. are retryable
                self._record_error(exc)
            if attempt < self.cfg.max_retries and not self._stop_event.is_set():
                self.metrics["retries"] += 1
                time.sleep(delay)
                delay = min(delay * 2, 60)
        self.metrics["failed"] += len(items)
        self._dead_letter(items, self.metrics["last_error"] or "delivery failed", "undeliverable", attempts)
        # the destination is down: don't try dead letters again before the backoff interval
        self._next_auto_at = max(self._next_auto_at, time.monotonic() + self._auto_backoff)

    def _delivered(self, n: int) -> None:
        self.metrics["sent"] += n
        self.metrics["last_success_at"] = now_iso()
        # the destination is accepting events: dead letters can go now
        if self._next_auto_at > time.monotonic():
            self._next_auto_at = time.monotonic()
            self._auto_backoff = self.cfg.auto_replay_interval_seconds

    def _ledger(self, output: str, outcome: str, trigger: str, events: List[Dict[str, Any]], detail: str = "") -> None:
        if self.ledger is not None and events:
            try:
                self.ledger.record(output, outcome, trigger, events, detail)
            except Exception:  # the ledger must never stop delivery
                logger.exception("delivery ledger write failed for %s", output)

    def _record_error(self, exc: Exception) -> None:
        self.metrics["last_error"] = f"{type(exc).__name__}: {exc}"[:500]
        self.metrics["last_error_at"] = now_iso()
        logger.warning("output %s: %s", self.cfg.name, self.metrics["last_error"])

    def _dead_letter(self, items: List[Item], reason: str, kind: str, attempts: int) -> None:
        self.store.append([entry(e, kind, reason, attempts, src, self.cfg.name) for e, src in items])
        self.metrics["dead_lettered"] += len(items)
        self._ledger(self.cfg.name, "dead_lettered", "queue_full" if kind == "queue_full" else "live",
                     [e for e, _ in items], f"{kind}: {reason}")

    # ---- dead-letter replay ---------------------------------------------------------------
    def _replay_send(self, entries: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
        """Deliver dead-letter entries once, no retries. Raises if the destination accepted nothing."""
        events = [e["event"] for e in entries]
        refused: List[Dict[str, Any]] = []
        try:
            self.send(events)
        except DeliveryError as exc:
            if not exc.rejected:
                raise
            refused_ids = {id(e) for e in exc.rejected}
            for e in entries:
                if id(e["event"]) in refused_ids:
                    e.update(kind="rejected", reason=str(exc)[:500], at=now_iso(),
                             attempts=int(e.get("attempts", 1)) + 1)
                    refused.append(e)
        refused_ids = {id(e["event"]) for e in refused}
        done = [e for e in events if id(e) not in refused_ids]
        self.metrics["resent"] += len(done)
        self.metrics["last_success_at"] = now_iso()
        trigger, owner = self._replay_ctx
        self._ledger(self.cfg.name, "delivered", trigger, done,
                     "re-sent from dead letters" if owner == self.cfg.name else f"dead letters of {owner}")
        if owner != self.cfg.name:  # the owning output's events are now accounted for elsewhere
            self._ledger(owner, "rerouted", trigger, done, f"delivered through {self.cfg.name}")
        self._ledger(owner, "dead_lettered", trigger, [e["event"] for e in refused], "rejected again on re-send")
        return len(done), refused

    def _execute(self, job: ReplayJob) -> None:
        job.progress["started_at"] = now_iso()
        self._replay_ctx = (job.trigger, job.store.name)
        try:
            job.store.replay(self._replay_send, batch_size=self.cfg.batch_size, kinds=job.kinds, limit=job.limit,
                             progress=job.progress, should_stop=self._stop_event.is_set)
        except Exception as exc:  # a broken file must not kill the sink
            logger.exception("replay of %s failed", job.store.name)
            job.progress.update(state="failed", error=f"{type(exc).__name__}: {exc}"[:500], finished_at=now_iso())
        job.progress["via"] = self.cfg.name
        self.last_replay = job.progress
        job.done.set()

    def _run_jobs(self) -> None:
        while True:
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                return
            self._execute(job)

    def _maybe_auto_replay(self) -> None:
        if not self.cfg.auto_replay or self.store.busy or time.monotonic() < self._next_auto_at:
            return
        if self.store.waiting(AUTO_KINDS) == 0:
            self._next_auto_at = time.monotonic() + self.cfg.auto_replay_interval_seconds
            return
        job = ReplayJob(self.store, AUTO_KINDS, self.cfg.batch_size * self.cfg.replay_batches_per_pass, "auto")
        self._execute(job)
        state = job.progress.get("state")
        if state == "limit_reached":
            self._next_auto_at = time.monotonic()           # more to do; live traffic gets a turn first
        elif state == "stopped" and job.progress.get("error"):
            self._next_auto_at = time.monotonic() + self._auto_backoff
            self._auto_backoff = min(self._auto_backoff * 2, self.cfg.auto_replay_max_interval_seconds)
        else:
            self._auto_backoff = self.cfg.auto_replay_interval_seconds
            self._next_auto_at = time.monotonic() + self._auto_backoff

    def request_replay(self, store: Optional[DeadLetterStore] = None, kinds: Tuple[str, ...] = KINDS,
                       limit: Optional[int] = None, wait: float = 30.0) -> Dict[str, Any]:
        """Re-send dead letters (this output's, or `store` on another output's behalf) through this output.
        Waits up to `wait` seconds; a longer replay carries on and reports through status()."""
        job = ReplayJob(store or self.store, tuple(kinds), limit, "manual")
        if self.is_alive():
            self._jobs.put(job)
            job.done.wait(timeout=wait)
        else:
            self._execute(job)
        return job.progress

    # ---- control --------------------------------------------------------------------------
    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self.join(timeout=timeout)

    def flush(self, timeout: float = 10.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.queue.empty() and self._idle.is_set():
                return True
            time.sleep(0.02)
        return False

    def test(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Deliver one event synchronously, bypassing the queue; used by the 'Send test event' button."""
        try:
            self.send([sample])
            return {"ok": True, "detail": f"delivered to {self.describe_target()}"}
        except Exception as exc:
            return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:500]}

    def status(self) -> Dict[str, Any]:
        dl = self.store.summary()
        return {"name": self.cfg.name, "type": self.type_name, "target": self.describe_target(),
                "enabled": self.cfg.enabled, "queue_depth": self.queue.qsize(), "alive": self.is_alive(),
                "dead_letter_file": str(self.dlq_path), **self.metrics,
                "dead_letters": {"waiting": dl["waiting"], "by_kind": dl["by_kind"],
                                 "auto_replay": self.cfg.auto_replay, "replay_running": dl["replay_running"],
                                 "last_replay": self.last_replay}}
