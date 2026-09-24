"""
The connector engine's promise for bursts and write failures: a record that does not fit in the
ingest queue, or whose batch fails to commit, is written to the spool on disk and ingested later.
A burst costs latency, never lines.
"""
import pytest

import backend.connectors.engine as engine_module
from backend.connectors.config import Pipeline, TracelogConfig
from backend.connectors.engine import ConnectorEngine
from backend.services.ingestion.stream import InboundRecord
from backend.services.integrity.ledger import IntegrityLedger


def records(n):
    return [InboundRecord(raw=f"<14>Sep 20 14:00:{i:02d} fw1 app: src=10.0.0.{i} action=allow".encode(),
                          transport="syslog-udp", input_name="burst") for i in range(n)]


@pytest.fixture
def engine(isolated_db, tmp_path, monkeypatch):
    eng = ConnectorEngine()
    eng.configure(TracelogConfig(pipeline=Pipeline(queue_size=5, batch_size=1000, flush_seconds=0.05),
                                 data_dir=str(tmp_path)))
    monkeypatch.setattr(eng, "ensure_worker", lambda: None)   # drive the worker by hand, deterministically
    return eng


def stored_lines(database):
    with database.get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]


def test_a_burst_bigger_than_the_queue_is_spooled_and_every_line_ingested(engine, isolated_db):
    engine.submit(records(12))
    assert engine._queue.qsize() == 5 and engine.metrics["spooled"] == 7 and engine._spool_path().exists()

    engine._stop_event.set()
    engine._run()                      # drains the queue
    engine._replay_spool()             # then the spool
    assert stored_lines(isolated_db) == 12
    assert not engine._spool_path().exists() and engine.metrics["replayed"] == 7
    assert IntegrityLedger.verify_chain().is_valid


def test_a_batch_that_fails_to_commit_is_spooled_and_ingested_later(engine, isolated_db, monkeypatch):
    real_ingest = engine.ingestor.ingest
    monkeypatch.setattr(engine_module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(engine.ingestor, "ingest", lambda batch: (_ for _ in ()).throw(OSError("disk full")))
    engine._process(records(3))
    assert stored_lines(isolated_db) == 0 and engine.metrics["failed_batches"] == 1
    assert engine.metrics["spooled"] == 3

    monkeypatch.setattr(engine.ingestor, "ingest", real_ingest)
    engine._replay_spool()
    assert stored_lines(isolated_db) == 3 and IntegrityLedger.verify_chain().is_valid
