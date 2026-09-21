"""
Output connector base: each sink runs in its own thread with a bounded queue,
batches events, retries with exponential backoff, and writes anything it
cannot deliver to a dead-letter file (one JSON line per event) instead of
dropping it. Metrics are exposed for the API and dashboard.
"""
import json
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.connectors.config import Output

logger = logging.getLogger("tracelog.outputs")


class DeliveryError(Exception):
    """Raised by send(); `retryable=False` sends the batch straight to the dead-letter file."""

    def __init__(self, message: str, retryable: bool = True, rejected: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.retryable = retryable
        self.rejected = rejected  # subset of the batch that was permanently refused


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Sink(threading.Thread):
    type_name = "base"
    description = ""

    def __init__(self, cfg: Output, data_dir: str = "data"):
        super().__init__(name=f"sink-{cfg.name}", daemon=True)
        self.cfg = cfg
        self.s = cfg.settings
        self.queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=cfg.queue_size)
        self.dlq_path = Path(data_dir) / "dead_letter" / f"{cfg.name}.ndjson"
        self._stop_event = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self.metrics: Dict[str, Any] = {"sent": 0, "failed": 0, "dead_lettered": 0, "retries": 0,
                                        "last_error": None, "last_error_at": None, "last_success_at": None}
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

    def put(self, ocsf: Dict[str, Any]) -> None:
        if not self.cfg.include_raw and "raw_data" in ocsf:
            ocsf = {k: v for k, v in ocsf.items() if k != "raw_data"}
        try:
            self.queue.put_nowait(ocsf)
            self._idle.clear()
        except queue.Full:
            self._dead_letter([ocsf], "queue full")

    # ---- worker loop ----------------------------------------------------------------------
    def run(self) -> None:
        while not self._stop_event.is_set() or not self.queue.empty():
            batch = self._take_batch()
            if not batch:
                self._idle.set()
                continue
            self._deliver(batch)
            if self.queue.empty():
                self._idle.set()
        self.close()

    def _take_batch(self) -> List[Dict[str, Any]]:
        batch: List[Dict[str, Any]] = []
        deadline = time.monotonic() + self.cfg.flush_seconds
        while len(batch) < self.cfg.batch_size:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            try:
                batch.append(self.queue.get(timeout=min(timeout, 0.25)))
            except queue.Empty:
                if batch or self._stop_event.is_set():
                    break
        return batch

    def _deliver(self, batch: List[Dict[str, Any]]) -> None:
        delay = self.cfg.retry_backoff_seconds
        for attempt in range(self.cfg.max_retries + 1):
            try:
                self.send(batch)
                self.metrics["sent"] += len(batch)
                self.metrics["last_success_at"] = _now()
                return
            except DeliveryError as exc:
                self._record_error(exc)
                if exc.rejected:
                    self._dead_letter(exc.rejected, str(exc))
                    rejected_ids = {id(e) for e in exc.rejected}
                    delivered = [e for e in batch if id(e) not in rejected_ids]
                    self.metrics["sent"] += len(delivered)
                    return
                if not exc.retryable:
                    break
            except Exception as exc:  # network errors etc. are retryable
                self._record_error(exc)
            if attempt < self.cfg.max_retries and not self._stop_event.is_set():
                self.metrics["retries"] += 1
                time.sleep(delay)
                delay = min(delay * 2, 60)
        self.metrics["failed"] += len(batch)
        self._dead_letter(batch, self.metrics["last_error"] or "delivery failed")

    def _record_error(self, exc: Exception) -> None:
        self.metrics["last_error"] = f"{type(exc).__name__}: {exc}"[:500]
        self.metrics["last_error_at"] = _now()
        logger.warning("output %s: %s", self.cfg.name, self.metrics["last_error"])

    def _dead_letter(self, events: List[Dict[str, Any]], reason: str) -> None:
        self.dlq_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dlq_path.open("a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps({"reason": reason, "at": _now(), "event": e}, default=str) + "\n")
        self.metrics["dead_lettered"] += len(events)

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
        return {"name": self.cfg.name, "type": self.type_name, "target": self.describe_target(),
                "enabled": self.cfg.enabled, "queue_depth": self.queue.qsize(), "alive": self.is_alive(),
                "dead_letter_file": str(self.dlq_path), **self.metrics}
