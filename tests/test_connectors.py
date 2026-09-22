"""
Connector tests: inputs (syslog UDP/TCP, HEC, OTLP, NDJSON, file tail), lossless
stream ingestion with source auto-registration, and every output type against
local mock servers standing in for the real products.
"""
import asyncio
import gzip
import json
import socket
import threading
import time
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.connectors.config import FileInput, Output, OutputFilter, SyslogInput, TracelogConfig, load_config
from backend.connectors.engine import ConnectorEngine
from backend.connectors.inputs.pollers import FileTailInput
from backend.connectors.inputs.syslog import SyslogStreamParser
from backend.connectors.outputs import build_sink
from backend.connectors.outputs.formats import cef, leef
from backend.services.ingestion.stream import InboundRecord, StreamIngestor, decode_raw
from backend.services.integrity.ledger import IntegrityLedger
from backend.services.normalization.ocsf_export import validate
from tests.conftest import free_port
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC, PAN_THREAT, PAN_TRAFFIC, SURICATA

SAMPLE_LINES = [PAN_TRAFFIC, PAN_THREAT, FORTI_TRAFFIC, ASA_DENY, SURICATA]


def ingest(lines, peer="192.0.2.50"):
    return StreamIngestor().ingest([InboundRecord(raw=l.encode() if isinstance(l, str) else l, transport="syslog-udp",
                                                  input_name="test", peer_ip=peer) for l in lines])


def out(name, type_, **settings):
    return Output(name=name, type=type_, batch_size=50, flush_seconds=0.05, max_retries=0,
                  retry_backoff_seconds=0.01, timeout_seconds=3, settings=settings)


# ------------------------------------------------------------------ framing and lossless storage
def test_rfc6587_framing_handles_octet_counting_and_lf_split_across_reads():
    p = SyslogStreamParser(65536)
    m1, m2, m3 = b"<14>1 - host app - - - first", b"<13>Sep 21 10:00:00 h second", b"<13>third"
    stream = f"{len(m1)} ".encode() + m1 + m2 + b"\n" + f"{len(m3)} ".encode() + m3
    got = []
    for i in range(0, len(stream), 7):  # deliver in awkward 7-byte chunks
        got += p.feed(stream[i:i + 7])
    got += p.flush()
    assert got == [m1, m2, m3]


def test_decode_keeps_bytes_exactly_and_only_strips_framing():
    raw = b"  <14>user=J\xf6rg action=deny \t"
    text, enc = decode_raw(raw + b"\r\n")
    assert enc == "latin-1" and text.encode(enc) == raw
    text, enc = decode_raw(b"  leading and trailing spaces  \n")
    assert enc == "utf-8" and text == "  leading and trailing spaces  "


def test_stream_ingest_is_lossless_chained_and_registers_sources(isolated_db):
    stored = ingest(SAMPLE_LINES + ["#fields ts uid id.orig_h", "\x00 not a log at all", "  <13>padded line  "])
    assert len(stored) == len(SAMPLE_LINES) + 3  # nothing dropped: '#' lines and junk are kept
    classes = [s.normalized["class_uid"] for s in stored]
    assert classes[:5] == [4001, 2004, 4001, 4001, 2004] and classes[-2] == 0
    for s in stored:
        assert validate(s.ocsf) == [], s.ocsf.get("class_name")
    with isolated_db.get_connection() as conn:
        raw = conn.execute("SELECT raw_text, transport, peer_ip, raw_encoding FROM raw_logs "
                           "WHERE raw_text LIKE '%padded%'").fetchone()
        names = {r["name"] for r in conn.execute("SELECT name FROM sources")}
    assert raw["raw_text"] == "  <13>padded line  " and raw["transport"] == "syslog-udp" and raw["peer_ip"] == "192.0.2.50"
    # named by the device's own hostname when the log carries one, otherwise by the sender address;
    # the PAN THREAT line has no hostname but comes from the same sender as PA-3220, so it joins that source
    assert {"Palo Alto Networks PAN-OS (PA-3220)", "Fortinet FortiGate (FGT-HQ)", "Cisco ASA (192.0.2.50)"} <= names
    assert not any(n.startswith("Palo Alto Networks PAN-OS (192") for n in names)
    assert IntegrityLedger.verify_chain().is_valid


def test_static_source_mapping_names_the_device(isolated_db):
    from backend.services.ingestion.stream import SourceResolver
    ing = StreamIngestor(SourceResolver([{"name": "HQ-FW", "match_ip": "10.0.0.1", "category": "firewall"}]))
    stored = ing.ingest([InboundRecord(raw=PAN_TRAFFIC.encode(), transport="syslog-udp", input_name="t",
                                       peer_ip="10.0.0.1")])
    assert stored[0].source_name == "HQ-FW"


# ------------------------------------------------------------------ engine with real sockets
class LoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    def run(self, coro, timeout=10):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


def test_syslog_udp_and_tcp_to_splunk_and_file_end_to_end(isolated_db, mock_http, tmp_path):
    udp_port, tcp_port = free_port(socket.SOCK_DGRAM), free_port()
    cfg = TracelogConfig(
        data_dir=str(tmp_path),
        outputs=[out("splunk", "splunk_hec", url=mock_http.url, token="t0k"),
                 out("archive", "file", path=str(tmp_path / "ocsf-%Y%m%d.ndjson"))],
    )
    cfg.inputs.syslog = [SyslogInput(name="u", protocol="udp", host="127.0.0.1", port=udp_port),
                         SyslogInput(name="t", protocol="tcp", host="127.0.0.1", port=tcp_port)]
    eng, lt = ConnectorEngine(), LoopThread()
    try:
        lt.run(eng.start(cfg))
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for line in (PAN_TRAFFIC, FORTI_TRAFFIC):
            u.sendto(line.encode(), ("127.0.0.1", udp_port))
        with socket.create_connection(("127.0.0.1", tcp_port)) as t:
            for line in (ASA_DENY, SURICATA):  # octet-counting framing, as rsyslog sends it
                b = line.encode()
                t.sendall(f"{len(b)} ".encode() + b)
        deadline = time.time() + 10
        while eng.metrics["ingested"] < 4 and time.time() < deadline:
            time.sleep(0.05)
        assert eng.flush(10)
        status = eng.status()
        assert status["pipeline"]["ingested"] == 4
        events = [json.loads(x) for b in mock_http.bodies("/services/collector/event")
                  for x in b.decode().splitlines() if x.strip()]
        assert len(events) == 4
        assert all(e["sourcetype"] == "ocsf:tracelog" and validate(e["event"]) == [] for e in events)
        assert mock_http.requests[0]["headers"]["Authorization"] == "Splunk t0k"
        archived = [json.loads(l) for f in tmp_path.glob("ocsf-*.ndjson") for l in f.read_text().splitlines()]
        assert len(archived) == 4
        assert {o["name"]: o["sent"] for o in status["outputs"]} == {"splunk": 4, "archive": 4}
    finally:
        lt.run(eng.stop())
        lt.close()


def test_file_tail_input_follows_rotation_and_remembers_offsets(isolated_db, tmp_path):
    log = tmp_path / "remote" / "pa.log"
    log.parent.mkdir()
    log.write_text(PAN_TRAFFIC + "\n")
    got = []
    cfg = FileInput(name="rsyslog", paths=[str(tmp_path / "remote" / "*.log")], start_at="beginning")
    tail = FileTailInput(cfg, got.extend, str(tmp_path / "state"))
    assert tail.poll_once() == 1
    with log.open("a") as fh:
        fh.write(FORTI_TRAFFIC + "\npartial line without newline")
    assert tail.poll_once() == 1                     # the partial line waits for its newline
    tail2 = FileTailInput(cfg, got.extend, str(tmp_path / "state"))  # restart: offsets persisted
    assert tail2.poll_once() == 0
    log.unlink()
    log.write_text(ASA_DENY + "\n")                  # rotation: new file at the same path
    assert tail2.poll_once() == 1
    assert [r.raw.decode() for r in got] == [PAN_TRAFFIC, FORTI_TRAFFIC, ASA_DENY]


# ------------------------------------------------------------------ HTTP receivers
@pytest.fixture
def api(isolated_db, tmp_path, monkeypatch):
    from backend.api import receivers
    from backend.main import app
    eng = ConnectorEngine()
    eng.configure(TracelogConfig(data_dir=str(tmp_path)))
    monkeypatch.setattr(receivers, "engine", eng)
    import backend.api.connectors as connectors_api
    monkeypatch.setattr(connectors_api, "engine", eng)
    return TestClient(app), eng


def test_hec_receiver_accepts_concatenated_events_and_raw(api):
    client, eng = api
    body = "".join(json.dumps({"event": l, "host": "fw1", "sourcetype": "pan:traffic"}) for l in (PAN_TRAFFIC, ASA_DENY))
    r = client.post("/services/collector/event", content=body)
    assert r.json() == {"text": "Success", "code": 0}
    r = client.post("/services/collector/raw", content=(FORTI_TRAFFIC + "\n" + SURICATA).encode())
    assert r.json()["code"] == 0
    assert client.get("/services/collector/health").json()["code"] == 17
    assert eng.flush(10) and eng.metrics["ingested"] == 4


def test_hec_receiver_enforces_tokens_when_configured(api):
    client, eng = api
    eng.config.inputs.http.tokens = ["secret"]
    body = json.dumps({"event": PAN_TRAFFIC})
    assert client.post("/services/collector/event", content=body).status_code == 401
    ok = client.post("/services/collector/event", content=body, headers={"Authorization": "Splunk secret"})
    assert ok.status_code == 200


def test_otlp_json_receiver(api):
    client, eng = api
    payload = {"resourceLogs": [{"resource": {"attributes": [{"key": "host.name", "value": {"stringValue": "fw9"}}]},
                                 "scopeLogs": [{"logRecords": [{"body": {"stringValue": PAN_TRAFFIC}},
                                                               {"body": {"stringValue": SURICATA}}]}]}]}
    r = client.post("/v1/logs", json=payload)
    assert r.status_code == 200 and r.json() == {"partialSuccess": {}}
    assert client.post("/v1/logs", content=b"\x0a\x00", headers={"Content-Type": "application/x-protobuf"}).status_code == 415
    assert eng.flush(10) and eng.metrics["ingested"] == 2


def test_receivers_accept_gzip_wrapped_events_and_forwarder_envelopes(api, isolated_db):
    import gzip
    client, eng = api
    # OpenTelemetry Collector gzips by default
    payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"body": {"stringValue": FORTI_TRAFFIC}}]}]}]}
    r = client.post("/v1/logs", content=gzip.compress(json.dumps(payload).encode()),
                    headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert r.status_code == 200
    # Cribl-style HEC event carrying the original line in _raw, on the Splunk forwarder path
    r = client.post("/services/collector/event/1.0", content=json.dumps({"event": {"_raw": ASA_DENY}}))
    assert r.json()["code"] == 0
    # Logstash http output (format => json_batch): the device line is in `message`, the device in host.name
    batch = [{"message": PAN_TRAFFIC.replace("PA-3220", "PA-EDGE"), "host": {"name": "relay-1"}, "@version": "1"},
             {"message": SURICATA, "host": "ids-sensor-2"}]
    r = client.post("/api/ingest/stream?message_field=message", json=batch)
    assert r.json() == {"accepted": 2}
    assert eng.flush(10) and eng.metrics["ingested"] == 4
    with isolated_db.get_connection() as conn:
        raws = {r["raw_text"] for r in conn.execute("SELECT raw_text FROM raw_logs")}
        names = {r["name"] for r in conn.execute("SELECT name FROM sources")}
    assert {FORTI_TRAFFIC, ASA_DENY, SURICATA} <= raws           # the original lines, not the envelopes
    assert "OISF Suricata (ids-sensor-2)" in names and "Palo Alto Networks PAN-OS (PA-EDGE)" in names


def test_ndjson_stream_endpoint_and_connector_status(api):
    client, eng = api
    r = client.post("/api/ingest/stream?source=Lab%20Firewall", content="\n".join(SAMPLE_LINES).encode())
    assert r.json() == {"accepted": 5}
    assert eng.flush(10)
    status = client.get("/api/connectors").json()
    assert status["pipeline"]["ingested"] == 5
    assert any(s["pack"] == "paloalto_panos" for s in status["supported_sources"])
    assert any(i["name"] == "http-stream" and i["received"] == 5 for i in status["inputs"])


# ------------------------------------------------------------------ outputs against mock products
@pytest.fixture
def ocsf_events(isolated_db):
    return [s.ocsf for s in ingest(SAMPLE_LINES)]


def run_sink(cfg, events, tmp_path):
    sink = build_sink(cfg, data_dir=str(tmp_path))
    sink.send(events)
    return sink


def test_elasticsearch_bulk_format_and_partial_rejection(mock_http, ocsf_events, tmp_path):
    def bulk(body):
        n = body.decode().count('{"create"')
        items = [{"create": {"status": 201}} for _ in range(n)]
        items[0] = {"create": {"status": 400, "error": {"type": "mapper_parsing_exception"}}}
        return 200, {"errors": True, "items": items}
    mock_http.responses["/_bulk"] = bulk
    cfg = out("os", "opensearch", url=mock_http.url, index="tracelog-%Y.%m", username="u", password="p")
    sink = build_sink(cfg, data_dir=str(tmp_path))
    sink._deliver([(e, "lab-fw") for e in ocsf_events])
    lines = mock_http.bodies("/_bulk")[0].decode().splitlines()
    assert json.loads(lines[0])["create"]["_index"].startswith("tracelog-20")
    assert json.loads(lines[0])["create"]["_id"] == ocsf_events[0]["metadata"]["uid"]  # idempotent re-sends
    assert "@timestamp" in json.loads(lines[1])
    assert mock_http.requests[0]["headers"]["Authorization"].startswith("Basic ")
    assert sink.metrics["dead_lettered"] == 1 and sink.metrics["sent"] == len(ocsf_events) - 1
    dead = [json.loads(l) for l in (tmp_path / "dead_letter" / "os.ndjson").read_text().splitlines()]
    assert len(dead) == 1 and dead[0]["kind"] == "rejected" and dead[0]["source"] == "lab-fw"


def test_loki_push_uses_low_cardinality_labels(mock_http, ocsf_events, tmp_path):
    run_sink(out("loki", "loki", url=mock_http.url, tenant="soc"), ocsf_events, tmp_path)
    req = mock_http.requests[0]
    assert req["path"] == "/loki/api/v1/push" and req["headers"]["X-Scope-OrgID"] == "soc"
    streams = json.loads(req["body"])["streams"]
    assert {tuple(sorted(s["stream"])) for s in streams} == {("job", "ocsf_class", "severity", "vendor")}
    assert sum(len(s["values"]) for s in streams) == len(ocsf_events)


def test_otlp_http_logs(mock_http, ocsf_events, tmp_path):
    run_sink(out("otel", "otlp_http", url=mock_http.url, headers={"api-key": "k"}), ocsf_events, tmp_path)
    req = mock_http.requests[0]
    assert req["path"] == "/v1/logs" and req["headers"]["api-key"] == "k"
    recs = json.loads(req["body"])["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(recs) == len(ocsf_events)
    finding = next(r for r in recs if '"class_uid":2004' in r["body"]["stringValue"])
    assert finding["severityNumber"] >= 17  # High/Critical findings map to ERROR/FATAL


def test_sentinel_logs_ingestion_api(mock_http, ocsf_events, tmp_path):
    mock_http.responses["/tenant-1/oauth2"] = (200, {"access_token": "AT", "expires_in": 3600})
    mock_http.responses["/dataCollectionRules"] = (204, b"")
    cfg = out("sentinel", "sentinel", tenant_id="tenant-1", client_id="c", client_secret="s",
              dce_endpoint=mock_http.url, dcr_immutable_id="dcr-1", stream_name="Custom-Tracelog_CL",
              authority=mock_http.url)
    run_sink(cfg, ocsf_events, tmp_path)
    post = [r for r in mock_http.requests if r["path"].startswith("/dataCollectionRules")][0]
    assert post["path"] == "/dataCollectionRules/dcr-1/streams/Custom-Tracelog_CL?api-version=2023-01-01"
    assert post["headers"]["Authorization"] == "Bearer AT"
    rows = json.loads(post["body"])
    assert rows[0]["TimeGenerated"].endswith("Z") and rows[0]["Ocsf"]["class_uid"] == 4001


def test_datadog_and_newrelic_presets(mock_http, ocsf_events, tmp_path):
    run_sink(out("dd", "datadog", api_key="DDKEY", url=mock_http.url + "/api/v2/logs"), ocsf_events, tmp_path)
    run_sink(out("nr", "newrelic", api_key="NRKEY", url=mock_http.url + "/log/v1"), ocsf_events, tmp_path)
    dd, nr = mock_http.requests
    assert dd["headers"]["DD-API-KEY"] == "DDKEY" and json.loads(dd["body"])[0]["ddsource"] == "tracelog"
    assert nr["headers"]["Api-Key"] == "NRKEY" and len(json.loads(nr["body"])[0]["logs"]) == len(ocsf_events)


def test_webhook_ndjson(mock_http, ocsf_events, tmp_path):
    run_sink(out("hook", "webhook", url=mock_http.url + "/hook", format="ndjson", bearer_token="B"), ocsf_events, tmp_path)
    req = mock_http.requests[0]
    assert req["headers"]["Authorization"] == "Bearer B"
    assert len(req["body"].decode().splitlines()) == len(ocsf_events)


def test_syslog_udp_cef_and_leef(udp_capture, ocsf_events, tmp_path):
    run_sink(out("cef", "syslog", host="127.0.0.1", port=udp_capture.port, protocol="udp", format="cef"),
             ocsf_events[:1], tmp_path)
    run_sink(out("leef", "syslog", host="127.0.0.1", port=udp_capture.port, protocol="udp", format="leef"),
             ocsf_events[:1], tmp_path)
    deadline = time.time() + 3
    while len(udp_capture.data) < 2 and time.time() < deadline:
        time.sleep(0.02)
    c, l = (d.decode() for d in udp_capture.data[:2])
    assert c.startswith("<") and " tracelog - OCSF4001 - CEF:0|TRACELOG|TRACELOG|1.0|4001" in c
    assert "src=10.20.4.5" in c and "dpt=443" in c
    assert "LEEF:2.0|TRACELOG|TRACELOG|1.0|4001" in l and "\tsrc=10.20.4.5" in l


def test_syslog_tcp_json_uses_octet_counting(tcp_capture, ocsf_events, tmp_path):
    sink = run_sink(out("wazuh", "syslog", host="127.0.0.1", port=tcp_capture.port, protocol="tcp", format="json"),
                    ocsf_events, tmp_path)
    sink.close()
    deadline = time.time() + 3
    while not tcp_capture.data and time.time() < deadline:
        time.sleep(0.02)
    time.sleep(0.2)
    frames = SyslogStreamParser(1 << 20).feed(tcp_capture.joined())
    assert len(frames) == len(ocsf_events)
    assert json.loads(frames[0].split(b" - ", 2)[2])["class_uid"] == 4001


def test_gelf_udp_compressed_and_tcp_null_delimited(udp_capture, tcp_capture, ocsf_events, tmp_path):
    run_sink(out("g1", "gelf", host="127.0.0.1", port=udp_capture.port, protocol="udp"), ocsf_events[:2], tmp_path)
    s = run_sink(out("g2", "gelf", host="127.0.0.1", port=tcp_capture.port, protocol="tcp"), ocsf_events[:2], tmp_path)
    s.close()
    deadline = time.time() + 3
    while (len(udp_capture.data) < 2 or not tcp_capture.data) and time.time() < deadline:
        time.sleep(0.02)
    time.sleep(0.2)
    g = json.loads(zlib.decompress(udp_capture.data[0]))
    assert g["version"] == "1.1" and g["_class_uid"] == 4001 and "short_message" in g
    tcp_msgs = [m for m in tcp_capture.joined().split(b"\x00") if m]
    assert len(tcp_msgs) == 2 and json.loads(tcp_msgs[1])["_class_uid"] == 2004


def test_file_and_parquet_outputs(ocsf_events, tmp_path):
    run_sink(out("f", "file", path=str(tmp_path / "x-%Y.ndjson")), ocsf_events, tmp_path)
    assert sum(len(p.read_text().splitlines()) for p in tmp_path.glob("x-*.ndjson")) == len(ocsf_events)
    pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq
    run_sink(out("p", "parquet", root=str(tmp_path / "lake")), ocsf_events, tmp_path)
    files = list((tmp_path / "lake").rglob("*.parquet"))
    rows = sum(pq.read_table(f).num_rows for f in files)
    assert rows == len(ocsf_events) and any("class_uid=2004" in str(f) for f in files)


def test_unreachable_output_retries_then_dead_letters(ocsf_events, tmp_path):
    cfg = out("down", "splunk_hec", url=f"http://127.0.0.1:{free_port()}", token="t")
    cfg.max_retries = 2
    sink = build_sink(cfg, data_dir=str(tmp_path))
    sink._deliver([(e, "") for e in ocsf_events])
    assert sink.metrics["retries"] == 2 and sink.metrics["failed"] == len(ocsf_events)
    dead = [json.loads(l) for l in (tmp_path / "dead_letter" / "down.ndjson").read_text().splitlines()]
    assert len(dead) == len(ocsf_events)
    assert all(d["kind"] == "undeliverable" and d["attempts"] == 3 and d["output"] == "down" for d in dead)


def test_output_filter_by_class_and_severity(ocsf_events, tmp_path):
    cfg = out("findings", "file", path=str(tmp_path / "f.ndjson"))
    cfg.filter = OutputFilter(classes=[2004], min_severity_id=3)
    sink = build_sink(cfg, data_dir=str(tmp_path))
    accepted = [e for e in ocsf_events if sink.accepts(e, "any")]
    assert accepted and all(e["class_uid"] == 2004 and e["severity_id"] >= 3 for e in accepted)


def test_cef_escaping():
    ev = {"class_uid": 2004, "type_uid": 200401, "severity_id": 5, "time": 0, "finding_info": {"title": "a|b\\c"},
          "message": "x=y\nz", "metadata": {}}
    line = cef(ev)
    assert "|a\\|b\\\\c|10|" in line and "msg=x\\=y\\nz" in line
    assert leef(ev).startswith("LEEF:2.0|TRACELOG|TRACELOG|1.0|200401|x09|")


def test_connector_test_endpoint_reports_delivery(api, mock_http):
    client, eng = api
    eng.sinks = [build_sink(out("hec", "splunk_hec", url=mock_http.url, token="t"), data_dir=eng.config.data_dir)]
    r = client.post("/api/connectors/outputs/hec/test").json()
    assert r["ok"] is True and r["ocsf_violations"] == []
    assert client.post("/api/connectors/outputs/missing/test").status_code == 404


def test_env_vars_are_expanded_in_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HEC_T", "from-env")
    p = tmp_path / "c.yaml"
    p.write_text("tracelog:\n  outputs:\n    - {name: s, type: splunk_hec, url: 'https://x:8088', token: '${HEC_T}',"
                 " batch_size: 10}\n")
    cfg = load_config(str(p))
    assert cfg.outputs[0].settings["token"] == "from-env" and cfg.outputs[0].batch_size == 10


def test_dotenv_fills_gaps_env_wins_and_blank_tokens_are_dropped(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('# secrets\nSPLUNK_T="from-dotenv"   # quoted\nexport DD=abc # comment\nEMPTY_T=""\nSHADOW=file\n')
    monkeypatch.setenv("TRACELOG_DOTENV", str(env))
    monkeypatch.setenv("SHADOW", "process-env")
    monkeypatch.setenv("BLANK", "")
    p = tmp_path / "c.yaml"
    p.write_text("tracelog:\n  inputs:\n    http: {tokens: ['${EMPTY_T}', '${UNSET_T}']}\n  outputs:\n"
                 "    - {name: s, type: splunk_hec, url: 'https://x', token: '${SPLUNK_T}', index: '${SHADOW}',"
                 " source: '${BLANK:-fallback}', sourcetype: '${DD}'}\n")
    cfg = load_config(str(p))
    s = cfg.outputs[0].settings
    assert (s["token"], s["index"], s["source"], s["sourcetype"]) == ("from-dotenv", "process-env", "fallback", "abc")
    assert cfg.inputs.http.tokens == []  # unset token variables must not turn into an empty, accepted token


def test_devices_behind_a_relay_are_told_apart_by_hostname(isolated_db):
    """rsyslog / Fluent Bit / Cribl relays: one sender address, several devices."""
    a = PAN_TRAFFIC.replace("PA-3220", "PA-DC1")
    b = PAN_TRAFFIC.replace("PA-3220", "PA-DC2")
    stored = ingest([a, b, PAN_THREAT], peer="10.9.9.9")
    assert [s.source_name for s in stored] == ["Palo Alto Networks PAN-OS (PA-DC1)",
                                               "Palo Alto Networks PAN-OS (PA-DC2)",
                                               "Palo Alto Networks PAN-OS (10.9.9.9)"]  # ambiguous: keep the relay


def test_connector_docs_are_generated_from_the_guides():
    """docs/CONNECTORS.md must match backend/connectors/guides.py (run scripts/generate_connector_docs.py)."""
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("gen", root / "scripts" / "generate_connector_docs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert (root / "docs" / "CONNECTORS.md").read_text(encoding="utf-8") == gen.build()
    assert "{host}" not in gen.build() and "{syslog_port}" not in gen.build()


def test_every_guide_names_a_real_pack_and_output_type():
    from backend.connectors.guides import DESTINATIONS, SOURCES
    from backend.connectors.outputs import SINK_TYPES
    from backend.services.vendors import SUPPORTED_SOURCES
    packs = {s["pack"] for s in SUPPORTED_SOURCES}
    assert all(s["pack"] in packs for s in SOURCES)
    import yaml
    for d in DESTINATIONS:
        blocks = yaml.safe_load(d["config"])
        assert all(b["type"] in SINK_TYPES for b in blocks), d["key"]


def test_forwarder_host_becomes_the_event_host_when_the_log_has_none(isolated_db):
    from backend.connectors.outputs.formats import hostname_of
    stored = StreamIngestor().ingest([
        InboundRecord(raw=SURICATA.encode(), transport="hec", input_name="hec", peer_ip="10.0.0.5",
                      hints={"hostname": "ids-sensor-9"}),
        InboundRecord(raw=PAN_TRAFFIC.encode(), transport="hec", input_name="hec", peer_ip="10.0.0.5",
                      hints={"hostname": "fluent-bit-relay"})])
    assert hostname_of(stored[0].ocsf) == "ids-sensor-9"   # Splunk host / syslog HOSTNAME downstream
    assert hostname_of(stored[1].ocsf) == "PA-3220"        # the device's own hostname wins over the relay's


def test_syslog_notice_is_low_not_medium():
    from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
    assert OCSFNormalizer.normalize_severity("notice") == (2, "Low")
    assert OCSFNormalizer.normalize_severity("warning") == (3, "Medium")
