"""
Dead letters: what gets recorded when a destination fails, and every way they are re-sent:
manual replay after recovery, replay while still down, rejected events, automatic re-send,
re-routing to another output, resuming after a crash, duplicate-free re-sends to an index,
and the API.
"""
import json
import time

import pytest
from fastapi.testclient import TestClient

from backend.connectors.config import Output, TracelogConfig
from backend.connectors.engine import ConnectorEngine
from backend.connectors.outputs import build_sink
from backend.connectors.outputs.deadletter import DeadLetterStore, entry
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC, PAN_THREAT, PAN_TRAFFIC, SURICATA

LINES = [PAN_TRAFFIC, PAN_THREAT, FORTI_TRAFFIC, ASA_DENY, SURICATA]


class Switch:
    """A destination that can be taken down and brought back."""

    def __init__(self, up=True, down_status=503):
        self.up, self.down_status = up, down_status
        self.accepted = []  # bodies the destination accepted

    def __call__(self, body):
        if not self.up:
            return self.down_status, {"text": "unavailable"}
        self.accepted.append(body)
        return 200, {"text": "Success", "code": 0}

    def events(self):
        return [json.loads(l)["event"] for b in self.accepted for l in b.decode().splitlines() if l.strip()]


def out(name, type_, **kw):
    settings = kw.pop("settings", {})
    base = dict(batch_size=2, flush_seconds=0.05, max_retries=1, retry_backoff_seconds=0.01, timeout_seconds=3,
                auto_replay=False, auto_replay_interval_seconds=0.2)
    return Output(name=name, type=type_, settings=settings, **{**base, **kw})


@pytest.fixture
def events(isolated_db):
    stored = StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t",
                                                    peer_ip="192.0.2.50") for l in LINES])
    return [(s.ocsf, s.source_name) for s in stored]


def started(cfg, tmp_path):
    sink = build_sink(cfg, data_dir=str(tmp_path))
    sink.start()
    return sink


def wait_for(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_outage_records_kind_source_attempts_and_reason(mock_http, events, tmp_path):
    mock_http.responses["/services"] = Switch(up=False)
    sink = started(out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}), tmp_path)
    try:
        for e, src in events:
            sink.put(e, src)
        assert wait_for(lambda: sink.metrics["dead_lettered"] == len(events))
    finally:
        sink.stop()
    lines = [json.loads(l) for l in (tmp_path / "dead_letter" / "splunk.ndjson").read_text().splitlines()]
    assert len(lines) == len(events)
    first = lines[0]
    assert first["kind"] == "undeliverable" and first["attempts"] == 2 and first["output"] == "splunk"
    assert "503" in first["reason"] and first["source"].startswith("Palo Alto Networks PAN-OS")
    assert first["event"]["metadata"]["uid"] == events[0][0]["metadata"]["uid"]
    s = sink.store.summary()
    assert s["waiting"] == len(events) and s["by_kind"]["undeliverable"] == len(events)
    assert s["by_source"] and s["top_reasons"][0]["count"] >= 1


def test_manual_replay_after_recovery_delivers_each_event_once(mock_http, events, tmp_path):
    switch = Switch(up=False)
    mock_http.responses["/services"] = switch
    sink = started(out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}), tmp_path)
    try:
        for e, src in events:
            sink.put(e, src)
        assert wait_for(lambda: sink.metrics["dead_lettered"] == len(events))
        switch.up = True
        result = sink.request_replay(wait=10)
    finally:
        sink.stop()
    assert result["state"] == "done" and result["delivered"] == len(events)
    uids = [e["metadata"]["uid"] for e in switch.events()]
    assert sorted(uids) == sorted(e["metadata"]["uid"] for e, _ in events)  # all of them, once each
    assert sink.store.summary()["waiting"] == 0 and sink.metrics["resent"] == len(events)
    assert not sink.store.claim_path.exists() and not sink.store.offset_path.exists()


def test_replay_while_destination_is_still_down_keeps_everything(mock_http, events, tmp_path):
    mock_http.responses["/services"] = Switch(up=False)
    sink = build_sink(out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}),
                      data_dir=str(tmp_path))
    sink._deliver(events)
    result = sink.request_replay()  # sink thread not started: runs inline
    assert result["state"] == "stopped" and result["delivered"] == 0 and "503" in result["error"]
    assert sink.store.summary()["waiting"] == len(events)
    # the next attempt picks up exactly where this one stopped
    mock_http.responses["/services"] = Switch(up=True)
    assert sink.request_replay()["delivered"] == len(events)
    assert sink.store.summary()["waiting"] == 0


def test_rejected_events_are_never_auto_resent_but_can_be_resent_on_request(mock_http, events, tmp_path):
    bad_token = Switch(up=False, down_status=403)
    mock_http.responses["/services"] = bad_token
    cfg = out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "wrong"}, auto_replay=True)
    sink = started(cfg, tmp_path)
    try:
        for e, src in events:
            sink.put(e, src)
        assert wait_for(lambda: sink.metrics["dead_lettered"] == len(events))
        assert sink.store.summary()["by_kind"]["rejected"] == len(events)
        bad_token.up = True           # e.g. the HEC token was fixed
        time.sleep(1.0)               # several auto-replay intervals pass
        assert sink.store.summary()["waiting"] == len(events)  # auto re-send leaves rejected events alone
        result = sink.request_replay(kinds=("rejected",), wait=10)
    finally:
        sink.stop()
    assert result["delivered"] == len(events) and sink.store.summary()["waiting"] == 0


def test_auto_replay_drains_the_backlog_when_the_destination_recovers(mock_http, events, tmp_path):
    switch = Switch(up=False)
    mock_http.responses["/services"] = switch
    cfg = out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}, auto_replay=True)
    sink = started(cfg, tmp_path)
    try:
        for e, src in events:
            sink.put(e, src)
        assert wait_for(lambda: sink.metrics["dead_lettered"] == len(events))
        switch.up = True               # destination back; nobody presses anything
        assert wait_for(lambda: sink.store.summary()["waiting"] == 0, timeout=15)
    finally:
        sink.stop()
    assert sorted(e["metadata"]["uid"] for e in switch.events()) == \
        sorted(e["metadata"]["uid"] for e, _ in events)
    assert sink.last_replay["trigger"] == "auto" and sink.last_replay["state"] == "done"


def test_auto_replay_backs_off_while_the_destination_stays_down(mock_http, events, tmp_path):
    mock_http.responses["/services"] = Switch(up=False)
    cfg = out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}, auto_replay=True,
              auto_replay_interval_seconds=0.1, auto_replay_max_interval_seconds=0.4)
    sink = build_sink(cfg, data_dir=str(tmp_path))
    sink._deliver(events)
    sink._next_auto_at = 0
    sink._maybe_auto_replay()
    assert sink.last_replay["state"] == "stopped" and sink._auto_backoff == pytest.approx(0.2)
    for _ in range(4):
        sink._next_auto_at = 0
        sink._maybe_auto_replay()
    assert sink._auto_backoff == pytest.approx(0.4)  # capped
    assert sink.store.summary()["waiting"] == len(events)


def test_replay_through_another_output(mock_http, events, tmp_path):
    mock_http.responses["/services"] = Switch(up=False)
    splunk = build_sink(out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}),
                        data_dir=str(tmp_path))
    splunk._deliver(events)
    archive = build_sink(out("archive", "file", settings={"path": str(tmp_path / "rescued.ndjson")}),
                         data_dir=str(tmp_path))
    result = archive.request_replay(splunk.store)
    assert result["delivered"] == len(events)
    assert len((tmp_path / "rescued.ndjson").read_text().splitlines()) == len(events)
    assert splunk.store.summary()["waiting"] == 0


def test_replay_resumes_after_a_crash_without_resending_delivered_batches(tmp_path):
    store = DeadLetterStore(tmp_path / "dead_letter" / "siem.ndjson")
    store.append([entry({"metadata": {"uid": f"e{i}"}, "time": 0}, "undeliverable", "down", 2) for i in range(7)])
    sent = []

    def crash_after_two_batches(batch):
        if len(sent) >= 4:
            raise SystemExit("power cut")          # not an Exception: the process dies mid-replay
        sent.extend(e["event"]["metadata"]["uid"] for e in batch)
        return len(batch), []

    with pytest.raises(SystemExit):
        store.replay(crash_after_two_batches, batch_size=2)
    assert store.claim_path.exists() and sent == ["e0", "e1", "e2", "e3"]

    restarted = DeadLetterStore(tmp_path / "dead_letter" / "siem.ndjson")   # a new process
    assert restarted.summary()["waiting"] == 3
    resent = []
    result = restarted.replay(lambda b: (resent.extend(e["event"]["metadata"]["uid"] for e in b) or len(b), []),
                              batch_size=2)
    assert result["state"] == "done" and resent == ["e4", "e5", "e6"]
    assert restarted.summary()["waiting"] == 0


def test_kind_filter_and_limit_leave_the_rest_waiting(tmp_path):
    store = DeadLetterStore(tmp_path / "dead_letter" / "q.ndjson")
    store.append([entry({"metadata": {"uid": f"u{i}"}}, "undeliverable", "down", 2) for i in range(5)] +
                 [entry({"metadata": {"uid": f"r{i}"}}, "rejected", "400", 1) for i in range(3)])
    got = []
    result = store.replay(lambda b: (got.extend(e["event"]["metadata"]["uid"] for e in b) or len(b), []),
                          batch_size=2, kinds=("undeliverable",), limit=4)
    assert result["state"] == "limit_reached" and got == ["u0", "u1", "u2", "u3"]
    s = store.summary()
    assert s["by_kind"] == {"undeliverable": 1, "queue_full": 0, "rejected": 3}
    result = store.replay(lambda b: (got.extend(e["event"]["metadata"]["uid"] for e in b) or len(b), []),
                          kinds=("undeliverable",))
    assert result["state"] == "done" and got[-1] == "u4" and store.summary()["by_kind"]["rejected"] == 3


def test_entries_written_before_kinds_existed_still_replay(tmp_path):
    path = tmp_path / "dead_letter" / "old.ndjson"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"reason": "ConnectError", "at": "2026-09-20T10:00:00+00:00",
                                "event": {"metadata": {"uid": "x"}}}) + "\n")
    store = DeadLetterStore(path)
    assert store.summary()["by_kind"]["undeliverable"] == 1
    assert store.replay(lambda b: (len(b), []))["delivered"] == 1


def test_index_resends_are_duplicate_free(mock_http, events, tmp_path):
    seen = set()

    def bulk(body):
        lines = body.decode().splitlines()
        items = []
        for action in lines[0::2]:
            _id = json.loads(action)["create"]["_id"]
            items.append({"create": {"status": 409 if _id in seen else 201}})
            seen.add(_id)
        return 200, {"errors": any(i["create"]["status"] != 201 for i in items), "items": items}

    mock_http.responses["/_bulk"] = bulk
    sink = build_sink(out("es", "elasticsearch", settings={"url": mock_http.url}), data_dir=str(tmp_path))
    sink._deliver(events)
    sink._deliver(events)          # the same events again, as after a crash mid-replay
    assert len(seen) == len(events)
    assert sink.metrics["sent"] == 2 * len(events) and sink.metrics["dead_lettered"] == 0


def test_dead_letter_api(isolated_db, mock_http, events, tmp_path, monkeypatch):
    import backend.api.connectors as connectors_api
    from backend.main import app
    mock_http.responses["/services"] = Switch(up=False)
    eng = ConnectorEngine()
    eng.configure(TracelogConfig(data_dir=str(tmp_path), outputs=[
        out("splunk", "splunk_hec", settings={"url": mock_http.url, "token": "t"}),
        out("archive", "file", settings={"path": str(tmp_path / "archive.ndjson")})]))
    monkeypatch.setattr(connectors_api, "engine", eng)
    splunk = eng.sinks[0]
    splunk._deliver(events)
    # an output that has since been removed from the config left dead letters behind
    DeadLetterStore(tmp_path / "dead_letter" / "old-qradar.ndjson").append(
        [entry(events[0][0], "undeliverable", "down", 6, events[0][1], "old-qradar")])
    client = TestClient(app)

    listing = {d["output"]: d for d in client.get("/api/connectors/dead-letters").json()}
    assert listing["splunk"]["waiting"] == len(events) and listing["splunk"]["configured"]
    assert listing["old-qradar"]["configured"] is False
    detail = client.get("/api/connectors/dead-letters/splunk?limit=2").json()
    assert len(detail["entries"]) == 2 and detail["entries"][0]["event"]["class_uid"]

    r = client.post("/api/connectors/dead-letters/splunk/replay").json()
    assert r["state"] == "stopped" and r["remaining"] == len(events)
    assert client.post("/api/connectors/dead-letters/splunk/replay?kinds=bogus").status_code == 400
    assert client.post("/api/connectors/dead-letters/old-qradar/replay").status_code == 404  # no such output

    r = client.post("/api/connectors/dead-letters/old-qradar/replay?to=archive").json()
    assert r["delivered"] == 1 and r["remaining"] == 0
    mock_http.responses["/services"] = Switch(up=True)
    r = client.post("/api/connectors/dead-letters/splunk/replay?kinds=undeliverable&limit=2").json()
    assert r["state"] == "limit_reached" and r["delivered"] == 2 and r["remaining"] == len(events) - 2
    r = client.post("/api/connectors/dead-letters/splunk/replay").json()
    assert r["state"] == "done" and r["remaining"] == 0
    status = {o["name"]: o for o in client.get("/api/connectors").json()["outputs"]}
    assert status["splunk"]["dead_letters"]["waiting"] == 0 and status["splunk"]["resent"] == len(events)
