"""
Pull-style inputs that run in background threads:
- FileTailInput: follows files matched by glob patterns (for example the
  per-device files an existing rsyslog or syslog-ng server already writes),
  survives rotation and truncation, and remembers its read offsets across
  restarts so no line is read twice or skipped;
- KafkaInput: consumes raw log topics (requires `kafka-python-ng`).
"""
import glob
import json
import logging
import os
import threading
from pathlib import Path
from typing import Callable, Dict, List

from backend.connectors.config import FileInput, KafkaInput as KafkaInputConfig
from backend.connectors.inputs.syslog import InputStats
from backend.services.ingestion.stream import InboundRecord

logger = logging.getLogger("tracelog.inputs")
Submit = Callable[[List[InboundRecord]], None]


class FileTailInput(threading.Thread):
    def __init__(self, cfg: FileInput, submit: Submit, state_dir: str):
        super().__init__(name=f"file-{cfg.name}", daemon=True)
        self.cfg, self.submit = cfg, submit
        self.stats = InputStats(cfg.name, "file", ", ".join(cfg.paths))
        self.state_path = Path(state_dir) / f"filetail-{cfg.name}.json"
        self.offsets: Dict[str, Dict[str, int]] = self._load()
        self._stop_event = threading.Event()

    def _load(self) -> Dict[str, Dict[str, int]]:
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.offsets))
        os.replace(tmp, self.state_path)

    def poll_once(self) -> int:
        total = 0
        for pattern in self.cfg.paths:
            for path in sorted(glob.glob(pattern)):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                state = self.offsets.get(path)
                if state is None or state.get("inode") != st.st_ino or st.st_size < state.get("offset", 0):
                    start = st.st_size if (state is None and self.cfg.start_at == "end") else 0
                    state = {"inode": st.st_ino, "offset": start}
                if st.st_size == state["offset"]:
                    self.offsets[path] = state
                    continue
                with open(path, "rb") as fh:
                    fh.seek(state["offset"])
                    chunk = fh.read(8 * 1024 * 1024)
                end = chunk.rfind(b"\n")
                if end < 0:
                    continue  # wait for the line to be completed
                lines = [l for l in chunk[: end + 1].split(b"\n") if l.strip()]
                state["offset"] += end + 1
                self.offsets[path] = state
                if lines:
                    self.submit([InboundRecord(raw=l, transport="file", input_name=self.cfg.name,
                                               hints={"file": path}) for l in lines])
                    self.stats.hit(len(lines), end + 1)
                    total += len(lines)
        self._save()
        return total

    def run(self) -> None:
        self.stats.info["running"] = True
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self.stats.error(str(exc))
                logger.exception("file input %s", self.cfg.name)
            self._stop_event.wait(self.cfg.poll_seconds)
        self.stats.info["running"] = False

    def stop(self) -> None:
        self._stop_event.set()


class KafkaConsumerInput(threading.Thread):
    def __init__(self, cfg: KafkaInputConfig, submit: Submit):
        super().__init__(name=f"kafka-{cfg.name}", daemon=True)
        self.cfg, self.submit = cfg, submit
        self.stats = InputStats(cfg.name, "kafka", f"kafka://{','.join(cfg.bootstrap_servers)}/{','.join(cfg.topics)}")
        self._stop_event = threading.Event()

    def run(self) -> None:
        try:
            from kafka import KafkaConsumer
        except ImportError:
            self.stats.error("kafka-python-ng is not installed")
            return
        try:
            consumer = KafkaConsumer(*self.cfg.topics, bootstrap_servers=self.cfg.bootstrap_servers,
                                     group_id=self.cfg.group_id, enable_auto_commit=False, **self.cfg.options)
        except Exception as exc:
            self.stats.error(f"could not connect: {exc}")
            return
        self.stats.info["running"] = True
        while not self._stop_event.is_set():
            polled = consumer.poll(timeout_ms=1000)
            recs = [InboundRecord(raw=m.value if isinstance(m.value, bytes) else str(m.value).encode(),
                                  transport="kafka", input_name=self.cfg.name,
                                  hints={"topic": tp.topic}) for tp, msgs in polled.items() for m in msgs]
            if recs:
                self.submit(recs)
                self.stats.hit(len(recs), sum(len(r.raw) for r in recs))
                consumer.commit()  # after hand-off to the ingest queue
        consumer.close()
        self.stats.info["running"] = False

    def stop(self) -> None:
        self._stop_event.set()
