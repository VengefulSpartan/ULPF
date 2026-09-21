"""
Delivery ledger, reconciliation and the audit report: every stored event must be accounted
for at every output (delivered, filtered out, waiting in dead letters or in flight), the
ledger must reveal tampering, and events left behind by a crash must be sent again.
"""
import asyncio
import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from backend.connectors.config import Output, OutputFilter, TracelogConfig
from backend.connectors.engine import ConnectorEngine
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.integrity.delivery_ledger import DeliveryLedger
from backend.services.integrity.reconcile import audit_report, reconcile
from tests.test_dead_letters import Switch
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC, PAN_THREAT, PAN_TRAFFIC, SURICATA

LINES = [PAN_TRAFFIC, PAN_THREAT, FORTI_TRAFFIC, ASA_DENY, SURICATA]


def out(name, type_, **kw):
    settings = kw.pop("settings", {})
    base = dict(batch_size=10, flush_seconds=0.05, max_retries=0, retry_backoff_seconds=0.01, timeout_seconds=3,
                auto_replay=False)
    return Output(name=name, type=type_, settings=settings, **{**base, **kw})


def records():
    return [InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t", peer_ip="192.0.2.50")
            for l in LINES]


@pytest.fixture
def estate(isolated_db, mock_http, tmp_path, monkeypatch):
    """A running engine with three outputs: a SIEM that starts down, an archive, a filtered alert feed."""
    import backend.connectors.engine as engine_module
    switch = Switch(up=False)
    mock_http.responses["/services"] = switch
    eng = ConnectorEngine()
    eng.configure(TracelogConfig(data_dir=str(tmp_path), outputs=[
        out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}),
        out("archive", "file", settings={"path": str(tmp_path / "archive.ndjson")}),
        out("alerts", "file", settings={"path": str(tmp_path / "alerts.ndjson")},
            filter=OutputFilter(classes=[2004]))]))
    monkeypatch.setattr(engine_module, "engine", eng)
    eng.ensure_worker()
    yield eng, switch
    asyncio.run(eng.stop())


def by_name(rec):
    return {o["output"]: o for o in rec["outputs"]}


def test_every_outcome_is_recorded_and_the_books_balance(estate):
    eng, switch = estate
    eng.submit(records())
    assert eng.flush(10)
    rec = reconcile()
    o = by_name(rec)
    assert rec["pipeline"]["normalized"] == rec["pipeline"]["hash_chained"] == 5 and rec["pipeline"]["consistent"]
    assert o["archive"]["delivered"] == 5 and o["archive"]["unaccounted"] == 0
    assert o["alerts"]["delivered"] == 2 and o["alerts"]["filtered"] == 3          # only Detection Findings
    assert o["splunk"]["dead_letter_waiting"] == 5 and o["splunk"]["delivered"] == 0  # the SIEM is down
    assert o["splunk"]["dead_letter_file_entries"] == 5 and not o["splunk"]["notes"]
    assert rec["all_accounted"] and "5 wait in dead letters" in rec["verdict"]      # waiting is accounted for
    assert rec["integrity"]["is_valid"] and rec["delivery_ledger"]["is_valid"]

    switch.up = True
    assert eng.replay_dead_letters("splunk", wait=10)["delivered"] == 5
    o = by_name(reconcile())
    assert o["splunk"]["delivered"] == 5 and o["splunk"]["resent"] == 5 and o["splunk"]["dead_letter_waiting"] == 0
    ex = reconcile()["exceptions"]
    assert ex[0]["output"] == "splunk" and ex[0]["trigger"] == "manual" and ex[0]["count"] == 5  # newest first
    assert ex[1]["outcome"] == "dead_lettered" and ex[1]["count"] == 5 and "503" in ex[1]["detail"]


def test_rerouted_dead_letters_count_as_accounted(estate):
    eng, _ = estate
    eng.submit(records())
    assert eng.flush(10)
    assert eng.replay_dead_letters("splunk", to="archive", wait=10)["delivered"] == 5
    o = by_name(reconcile())
    assert o["splunk"]["rerouted"] == 5 and o["splunk"]["unaccounted"] == 0
    assert o["archive"]["duplicates"] == 5  # the archive now holds those events twice, and says so
    assert any("more than once" in n for n in o["archive"]["notes"])


def test_events_left_behind_by_a_crash_are_found_and_sent_again(estate, isolated_db):
    eng, switch = estate
    switch.up = True
    # stored but never handed to the outputs: what an in-memory queue holds when the process dies
    StreamIngestor().ingest(records())
    rec = reconcile()
    assert not rec["all_accounted"] and by_name(rec)["archive"]["unaccounted"] == 5
    assert "5 events unaccounted for at archive" in rec["verdict"]
    eng.start_recovery()
    deadline = time.time() + 10
    while eng.recovery["state"] == "running" and time.time() < deadline:
        time.sleep(0.05)
    assert eng.flush(10)
    rec = reconcile()
    o = by_name(rec)
    assert rec["all_accounted"], rec["verdict"]
    assert o["archive"]["delivered"] == 5 and o["splunk"]["delivered"] == 5
    assert o["alerts"]["delivered"] == 2 and o["alerts"]["filtered"] == 3
    assert eng.recovery["requeued"] == 12 and eng.recovery["filtered"] == 3


def test_outputs_only_owe_events_stored_after_they_were_added(isolated_db, tmp_path):
    StreamIngestor().ingest(records())  # history from before the output existed
    reg = DeliveryLedger.register_output("late-siem", "splunk_hec", "x")
    assert reg["first_seq"] == 6
    counts = DeliveryLedger.output_counts("late-siem", reg["first_seq"], 5)
    assert counts["owed"] == 0 and counts["without_outcome"] == 0


@pytest.mark.parametrize("tamper, problem", [
    ("UPDATE delivery_events SET outcome = 'delivered' WHERE rowid = (SELECT MIN(rowid) FROM delivery_events "
     "WHERE outcome = 'dead_lettered')", "outcome was edited"),
    ("DELETE FROM delivery_events WHERE rowid = (SELECT MIN(rowid) FROM delivery_events)", "event rows"),
    ("DELETE FROM delivery_batches WHERE id = (SELECT MIN(id) FROM delivery_batches)", "chain broken"),
    ("UPDATE delivery_batches SET trigger = 'manual' WHERE id = (SELECT MIN(id) FROM delivery_batches)",
     "batch record edited"),
])
def test_tampering_with_the_delivery_ledger_is_detected(estate, isolated_db, tamper, problem):
    eng, _ = estate
    eng.submit(records())
    assert eng.flush(10)
    assert DeliveryLedger.verify()["is_valid"]
    with isolated_db.get_connection() as conn:
        conn.execute(tamper)
        conn.commit()
    v = DeliveryLedger.verify()
    assert not v["is_valid"] and any(problem in i["problem"] for i in v["issues"])
    rec = reconcile()
    assert not rec["all_accounted"] and "delivery ledger failed verification" in rec["verdict"]


def test_events_from_the_upload_and_api_path_reach_the_outputs(estate, isolated_db, monkeypatch):
    import backend.services.ingestion.pipeline as pipeline_module
    from backend.services.ingestion.pipeline import IngestionPipeline
    monkeypatch.setattr(pipeline_module, "db", isolated_db)
    eng, switch = estate
    switch.up = True
    with isolated_db.get_connection() as conn:
        conn.execute("INSERT INTO sources (id, name, vendor, product, format_type, category, is_active, created_at, "
                     "event_count) VALUES ('s1', 'Lab upload', 'Palo Alto Networks', 'PAN-OS', 'csv', 'firewall', 1, "
                     "datetime('now'), 0)")
        conn.commit()
    IngestionPipeline.ingest_single_log(PAN_TRAFFIC, "s1", "Palo Alto Networks", "PAN-OS")
    assert eng.flush(10)
    o = by_name(reconcile())
    assert o["archive"]["delivered"] == 1 and o["splunk"]["delivered"] == 1 and o["alerts"]["filtered"] == 1


def test_audit_report_fingerprint_and_downloads(estate):
    from backend.main import app
    eng, _ = estate
    eng.submit(records())
    assert eng.flush(10)
    r = audit_report()
    body = {k: v for k, v in r.items() if k != "fingerprint"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    assert hashlib.sha256(canonical.encode()).hexdigest() == r["fingerprint"]["report_sha256"]
    assert r["fingerprint"]["delivery_ledger_head"] == DeliveryLedger.verify()["head_hash"]
    assert r["fingerprint"]["integrity_chain_head"]

    client = TestClient(app)
    j = client.get("/api/audit/report.json")
    assert j.status_code == 200 and "attachment" in j.headers["content-disposition"]
    assert json.loads(j.content)["outputs"]
    pdf = client.get("/api/audit/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and len(pdf.content) > 3000
    rec = client.get("/api/audit/reconcile").json()
    assert {o["output"] for o in rec["outputs"]} == {"splunk", "archive", "alerts"}
    assert client.get("/api/audit/delivery/verify").json()["is_valid"]
