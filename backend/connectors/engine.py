"""
Connector engine: owns the inputs, the ingest worker and the output router.

    inputs --submit()--> ingest queue --worker--> StreamIngestor (archive, parse,
    normalise, hash-chain, one transaction per batch) --> router --> sinks

If the ingest queue is full (a burst bigger than it can absorb), records are
spooled to disk and replayed when the worker catches up, so a burst never
drops logs. Sinks have their own queues, retries and dead-letter files.
"""
import asyncio
import base64
import json
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.connectors.config import TracelogConfig, load_config
from backend.connectors.inputs.pollers import FileTailInput, KafkaConsumerInput
from backend.connectors.inputs.syslog import SyslogListener
from backend.connectors.outputs import COMPATIBILITY, Sink, build_sink
from backend.connectors.outputs.deadletter import KINDS, DeadLetterStore
from backend.services.integrity.delivery_ledger import DeliveryLedger
from backend.services.normalization.ocsf_export import to_ocsf
from backend.services.ingestion.stream import InboundRecord, SourceResolver, StoredEvent, StreamIngestor, utcnow_iso
from backend.services.vendors import SUPPORTED_SOURCES

logger = logging.getLogger("tracelog.engine")


class ConnectorEngine:
    def __init__(self):
        self.config: TracelogConfig = TracelogConfig()
        self.sinks: List[Sink] = []
        self.sink_errors: List[Dict[str, str]] = []
        self.syslog: List[SyslogListener] = []
        self.pollers: List[Any] = []
        self.http_stats: Dict[str, Dict[str, Any]] = {}
        self._orphan_stores: Dict[str, DeadLetterStore] = {}
        self.recovery: Dict[str, Any] = {"state": "idle", "requeued": 0, "filtered": 0, "outputs": {}}
        self._source_names: Dict[str, str] = {}
        self._queue: "queue.Queue[InboundRecord]" = queue.Queue(maxsize=200000)
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pending = 0
        self._pending_lock = threading.Lock()
        self._lock = threading.Lock()
        self.ingestor = StreamIngestor()
        self.metrics: Dict[str, Any] = {"received": 0, "ingested": 0, "failed_batches": 0, "spooled": 0,
                                        "replayed": 0, "last_batch_ms": None, "last_error": None,
                                        "started_at": None}
        self._rate: List[tuple] = []

    # ---- lifecycle ------------------------------------------------------------------------
    def configure(self, config: Optional[TracelogConfig] = None) -> None:
        self.config = config or load_config()
        self._queue = queue.Queue(maxsize=self.config.pipeline.queue_size)
        self.ingestor = StreamIngestor(SourceResolver([s.model_dump() for s in self.config.sources]))
        self.sinks, self.sink_errors = [], []
        self._orphan_stores = {}
        for out in self.config.outputs:
            if not out.enabled:
                continue
            try:
                sink = build_sink(out, self.config.data_dir)
                sink.ledger = DeliveryLedger
                DeliveryLedger.register_output(sink.cfg.name, sink.type_name, sink.describe_target())
                self.sinks.append(sink)
            except Exception as exc:  # a bad output must not stop ingestion
                self.sink_errors.append({"name": out.name, "type": out.type, "error": str(exc)})
                logger.error("output %s not started: %s", out.name, exc)

    def ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._stop_event.clear()
                self._worker = threading.Thread(target=self._run, name="ingest-worker", daemon=True)
                self._worker.start()
                self.metrics["started_at"] = self.metrics["started_at"] or utcnow_iso()
            for s in self.sinks:
                if s.ident is None:
                    s.start()

    async def start(self, config: Optional[TracelogConfig] = None) -> None:
        self.configure(config)
        self.ensure_worker()
        self.start_recovery()
        for cfg in self.config.inputs.syslog:
            listener = SyslogListener(cfg, self.submit)
            await listener.start()
            self.syslog.append(listener)
        state_dir = str(Path(self.config.data_dir) / "state")
        for cfg in self.config.inputs.files:
            p = FileTailInput(cfg, self.submit, state_dir)
            p.start()
            self.pollers.append(p)
        for cfg in self.config.inputs.kafka:
            p = KafkaConsumerInput(cfg, self.submit)
            p.start()
            self.pollers.append(p)

    async def stop(self) -> None:
        for listener in self.syslog:
            await listener.stop()
        for p in self.pollers:
            p.stop()
        self.flush(timeout=10)
        self._stop_event.set()
        if self._worker:
            self._worker.join(timeout=5)
        for s in self.sinks:
            s.stop()
        self.syslog, self.pollers = [], []

    # ---- ingest ---------------------------------------------------------------------------
    def _add_pending(self, n: int) -> None:
        with self._pending_lock:
            self._pending += n

    def submit(self, records: List[InboundRecord]) -> None:
        self.ensure_worker()
        self.metrics["received"] += len(records)
        self._add_pending(len(records))
        overflow = []
        for r in records:
            try:
                self._queue.put_nowait(r)
            except queue.Full:
                overflow.append(r)
        if overflow:
            self._spool(overflow)
            self._add_pending(-len(overflow))  # counted again when replayed

    def _spool_path(self) -> Path:
        return Path(self.config.data_dir) / "spool" / "overflow.ndjson"

    def _spool(self, records: List[InboundRecord]) -> None:
        path = self._spool_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps({"raw": base64.b64encode(r.raw).decode(), "transport": r.transport,
                                     "input_name": r.input_name, "peer_ip": r.peer_ip, "peer_port": r.peer_port,
                                     "received_at": r.received_at, "hints": r.hints}) + "\n")
        self.metrics["spooled"] += len(records)

    def _replay_spool(self) -> None:
        path = self._spool_path()
        if not path.exists() or self._queue.qsize() > self._queue.maxsize // 2:
            return
        work = path.with_suffix(".replaying")
        path.rename(work)
        batch = []
        for line in work.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            batch.append(InboundRecord(raw=base64.b64decode(d["raw"]), transport=d["transport"],
                                       input_name=d["input_name"], peer_ip=d.get("peer_ip"),
                                       peer_port=d.get("peer_port"), received_at=d["received_at"],
                                       hints=d.get("hints") or {}))
        work.unlink()
        self.metrics["replayed"] += len(batch)
        self._add_pending(len(batch))
        for i in range(0, len(batch), self.config.pipeline.batch_size):
            self._process(batch[i:i + self.config.pipeline.batch_size])

    def _run(self) -> None:
        cfg = self.config.pipeline
        while not self._stop_event.is_set() or not self._queue.empty():
            batch: List[InboundRecord] = []
            deadline = time.monotonic() + cfg.flush_seconds
            while len(batch) < cfg.batch_size:
                try:
                    batch.append(self._queue.get(timeout=max(0.0, min(0.1, deadline - time.monotonic()))))
                except queue.Empty:
                    if batch or time.monotonic() >= deadline or self._stop_event.is_set():
                        break
            if batch:
                self._process(batch)
            else:
                self._replay_spool()

    def _process(self, batch: List[InboundRecord]) -> None:
        t0 = time.monotonic()
        try:
            stored = self.ingestor.ingest(batch)
        except Exception as exc:
            logger.exception("ingest batch failed; spooling %d records for retry", len(batch))
            self.metrics["failed_batches"] += 1
            self.metrics["last_error"] = f"{type(exc).__name__}: {exc}"[:300]
            self._spool(batch)
            self._add_pending(-len(batch))
            time.sleep(1)
            return
        finally_n = len(batch)
        ms = (time.monotonic() - t0) * 1000
        self.metrics["ingested"] += len(stored)
        self.metrics["last_batch_ms"] = round(ms, 1)
        now = time.monotonic()
        self._rate.append((now, len(stored)))
        self._rate = [(t, n) for t, n in self._rate if now - t <= 10]
        self.route(stored)
        self._add_pending(-finally_n)

    def route(self, stored: List[Any]) -> None:
        """Hand stored events (objects with .ocsf and .source_name) to every output that accepts them;
        record the ones an output's filter excludes, so they count as accounted for."""
        filtered: Dict[str, List[Dict[str, Any]]] = {}
        for ev in stored:
            for sink in self.sinks:
                if sink.accepts(ev.ocsf, ev.source_name):
                    sink.put(ev.ocsf, ev.source_name)
                else:
                    filtered.setdefault(sink.cfg.name, []).append(ev.ocsf)
        for name, events in filtered.items():
            try:
                DeliveryLedger.record(name, "filtered", "filter", events)
            except Exception:
                logger.exception("delivery ledger write failed")

    def route_normalized(self, normalized: Dict[str, Any], source_id: Optional[str] = None) -> None:
        """For events stored by the interactive API / upload path, so they reach the outputs too."""
        if not self.sinks:
            return  # not running here (e.g. dashboard in direct mode): recovery sends them at next start
        from types import SimpleNamespace
        self.route([SimpleNamespace(ocsf=to_ocsf(normalized), source_name=self._source_name(source_id))])

    def _source_name(self, source_id: Optional[str]) -> str:
        if not source_id:
            return ""
        if source_id not in self._source_names:
            from backend.services.storage import db as db_module
            with db_module.db.get_connection() as conn:
                row = conn.execute("SELECT name FROM sources WHERE id = ?", (source_id,)).fetchone()
            self._source_names[source_id] = row["name"] if row else ""
        return self._source_names[source_id]

    # ---- recovery after a restart ---------------------------------------------------------
    def start_recovery(self) -> None:
        """Events an output owed but never finished (queued in memory when TRACELOG stopped, or stored
        while outputs were not running) are sent again from the archive, in the background."""
        from backend.services.storage import db as db_module
        with db_module.db.get_connection() as conn:
            upto = conn.execute("SELECT MAX(sequence_num) FROM normalized_events").fetchone()[0] or 0
        self.recovery = {"state": "running", "upto_seq": upto, "requeued": 0, "filtered": 0, "outputs": {},
                         "started_at": utcnow_iso()}
        threading.Thread(target=self._recover, args=(upto,), name="delivery-recovery", daemon=True).start()

    def _recover(self, upto: int) -> None:
        try:
            for sink in list(self.sinks):
                after, requeued, filtered = 0, 0, []
                while not self._stop_event.is_set():
                    rows = [r for r in DeliveryLedger.owed_without_outcome(sink.cfg.name, after) if
                            r["sequence_num"] <= upto]
                    if not rows:
                        break
                    for r in rows:
                        after = r["sequence_num"]
                        ocsf = to_ocsf(json.loads(r["normalized_json"]))
                        source = r.get("source_name") or ""
                        if not sink.accepts(ocsf, source):
                            filtered.append(ocsf)
                        elif sink.put_blocking(ocsf, source):
                            requeued += 1
                    if filtered:
                        DeliveryLedger.record(sink.cfg.name, "filtered", "filter", filtered)
                        self.recovery["filtered"] += len(filtered)
                        filtered = []
                self.recovery["outputs"][sink.cfg.name] = requeued
                self.recovery["requeued"] += requeued
            self.recovery["state"] = "done"
        except Exception as exc:
            logger.exception("delivery recovery failed")
            self.recovery.update(state="failed", error=f"{type(exc).__name__}: {exc}"[:300])
        self.recovery["finished_at"] = utcnow_iso()

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until everything received so far is ingested and handed to every sink."""
        end = time.monotonic() + timeout
        while time.monotonic() < end and self._pending > 0:
            time.sleep(0.02)
        drained = self._pending <= 0
        return all(s.flush(max(0.1, end - time.monotonic())) for s in self.sinks) and drained

    # ---- status ---------------------------------------------------------------------------
    def eps(self) -> float:
        now = time.monotonic()
        recent = [(t, n) for t, n in self._rate if now - t <= 10]
        return round(sum(n for _, n in recent) / 10.0, 1)

    def status(self) -> Dict[str, Any]:
        inputs = [l.stats.info for l in self.syslog] + [p.stats.info for p in self.pollers]
        inputs += [{"name": k, **v} for k, v in self.http_stats.items()]
        return {
            "pipeline": {**self.metrics, "queue_depth": self._queue.qsize(), "pending": self._pending,
                         "events_per_second_10s": self.eps(),
                         "worker_alive": bool(self._worker and self._worker.is_alive())},
            "inputs": inputs,
            "http_receivers": {"enabled": self.config.inputs.http.enabled,
                               "authentication": "token" if self.config.inputs.http.tokens else "none (lab mode)",
                               "endpoints": ["/services/collector/event", "/services/collector/raw",
                                             "/v1/logs", "/api/ingest/stream"]},
            "outputs": [{**s.status(), "in_flight": s.in_flight} for s in self.sinks]
                       + [{**e, "alive": False} for e in self.sink_errors],
            "recovery": self.recovery,
            "supported_sources": SUPPORTED_SOURCES,
            "output_compatibility": COMPATIBILITY,
        }

    # ---- dead letters --------------------------------------------------------------------
    def dead_letter_stores(self) -> Dict[str, DeadLetterStore]:
        """Every output's store, plus files left by outputs that are no longer configured."""
        stores = {s.cfg.name: s.store for s in self.sinks}
        folder = Path(self.config.data_dir) / "dead_letter"
        if folder.is_dir():
            names = {p.name[: -len(".ndjson")] for p in folder.glob("*.ndjson")}
            names |= {p.name[: -len(".replaying.ndjson")] for p in folder.glob("*.replaying.ndjson")}
            for name in sorted(names):
                if name.endswith(".replaying") or name in stores:
                    continue
                if name not in self._orphan_stores:
                    self._orphan_stores[name] = DeadLetterStore(folder / f"{name}.ndjson")
                stores[name] = self._orphan_stores[name]
        return stores

    def dead_letters(self) -> List[Dict[str, Any]]:
        sinks = {s.cfg.name: s for s in self.sinks}
        out = []
        for name, store in self.dead_letter_stores().items():
            sink = sinks.get(name)
            out.append({**store.summary(), "configured": sink is not None,
                        "type": sink.type_name if sink else None,
                        "auto_replay": bool(sink and sink.cfg.auto_replay),
                        "last_replay": sink.last_replay if sink else None})
        return out

    def replay_dead_letters(self, name: str, to: Optional[str] = None, kinds: Optional[List[str]] = None,
                            limit: Optional[int] = None, wait: float = 30.0) -> Dict[str, Any]:
        """Re-send `name`'s dead letters through output `to` (default: the same output)."""
        stores = self.dead_letter_stores()
        if name not in stores:
            raise LookupError(f"no dead letters for '{name}'")
        sinks = {s.cfg.name: s for s in self.sinks}
        via = sinks.get(to or name)
        if via is None:
            raise LookupError(f"output '{to or name}' is not running; pick a configured output with to=")
        bad = [k for k in (kinds or []) if k not in KINDS]
        if bad:
            raise ValueError(f"unknown kind(s) {bad}; use {', '.join(KINDS)}")
        return via.request_replay(stores[name], tuple(kinds or KINDS), limit, wait)

    def http_hit(self, name: str, n: int, size: int) -> None:
        s = self.http_stats.setdefault(name, {"type": "http", "received": 0, "bytes": 0, "last_received_at": None,
                                              "running": True})
        s["received"] += n
        s["bytes"] += size
        s["last_received_at"] = utcnow_iso()


engine = ConnectorEngine()


def run_coroutine(coro) -> Any:
    """Helper for scripts: run an engine coroutine outside an event loop."""
    return asyncio.run(coro)
