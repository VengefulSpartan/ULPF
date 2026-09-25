"""
AI/ML readiness (docs/ML_DATA.md): the analytics row, the window features and the baseline detector.

What must hold:
- the Parquet row keeps the contract: typed columns, null where the device did not say (never 0),
  where each value came from, and the way back to the raw line;
- a window's features come from its own events and earlier ones only;
- the baseline flags what is far above its history and nothing below the minimum increase, and says
  what it compared with instead of giving a confidence;
- a flag is written once, through the one writer, as a valid OCSF Detection Finding whose evidence
  resolves to archived lines, and the chain still verifies.
"""
import hashlib
import json

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.ml import baseline, features as feat
from backend.services.ml.rows import COLUMNS, NAMES, ml_row, typed
from backend.services.normalization.ocsf_export import to_ocsf, validate
from backend.services.parsing.dispatch import parse_log
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC, FORTI_VPN_FAIL, PAN_TRAFFIC

MIN = 60 * 1000
T0 = 1789948800000            # 2026-09-21T00:00:00Z


def ingest(lines, peer="192.0.2.9"):
    return StreamIngestor().ingest([InboundRecord(raw=l.encode("utf-8"), transport="syslog-udp", input_name="syslog",
                                                  peer_ip=peer) for l in lines])


# --- the data contract -------------------------------------------------------------------------------

def test_the_row_says_where_each_value_came_from_and_leads_back_to_the_raw_line(isolated_db):
    stored = ingest([PAN_TRAFFIC, ASA_DENY, FORTI_VPN_FAIL, "something happened on host 10.1.2.3"])
    pan, asa, vpn, text = (ml_row(s.ocsf) for s in stored)

    assert list(pan) == NAMES
    assert pan["bytes_out"] == 1200 and pan["bytes_in"] == 8600 and pan["device_hostname"] == "PA-3220"
    assert pan["parser"] == "paloalto_panos" and pan["fields_verified"] is True
    assert pan["raw_sha256"] == stored[0].raw_hash == hashlib.sha256(PAN_TRAFFIC.encode()).hexdigest()
    assert pan["sequence_num"] == stored[0].sequence_num and pan["event_uid"] == stored[0].event_id
    assert pan["time_source"] == "device"

    # the ASA deny reports no bytes: null, not 0
    assert asa["bytes_in"] is None and asa["bytes_out"] is None
    assert asa["action_id"] == 2 and asa["disposition_id"] == 2

    assert vpn["class_uid"] == 3002 and vpn["status_id"] == 2 and vpn["user_name"] == "bob"

    # a line no pack knows: fields inferred, not verified; no time in it, so the time is the arrival's
    assert text["fields_verified"] is False and text["parser"] == "generic_inferred"
    assert text["time_source"] == "received"


def test_parquet_files_have_every_contract_column_with_its_type_even_when_no_event_has_a_value(tmp_path):
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    from backend.connectors.config import Output
    from backend.connectors.outputs.file_sinks import ParquetSink

    fmt, parsed = parse_log(ASA_DENY)
    from backend.services.normalization.ocsf_normalizer import OCSFNormalizer
    ev = OCSFNormalizer.normalize(parsed, ASA_DENY, "raw-1", "ab" * 32).model_dump()
    ev["id"] = "event-1"
    sink = ParquetSink(Output(name="lake", type="parquet", settings={"root": str(tmp_path / "lake")}),
                       data_dir=str(tmp_path))
    sink.send([to_ocsf(ev)])
    (path,) = list((tmp_path / "lake").rglob("*.parquet"))
    table = pq.read_table(path)
    assert table.column_names == NAMES
    kinds = {"int64": pa.int64(), "int32": pa.int32(), "string": pa.string(), "bool": pa.bool_()}
    for name, kind, _ in COLUMNS:
        assert table.schema.field(name).type == kinds[kind], name
    row = table.to_pylist()[0]
    assert row["bytes_out"] is None and row["dst_port"] == 3389 and row["raw_sha256"] == "ab" * 32


def test_a_value_of_the_wrong_type_becomes_null_in_its_column_but_stays_in_the_whole_event():
    row = typed({"dst_port": "not-a-port", "src_port": "443", "fields_verified": 1, "vendor": 7})
    assert row == {"dst_port": None, "src_port": 443, "fields_verified": True, "vendor": "7"}


# --- window features -----------------------------------------------------------------------------------

def _events(rows):
    base = {"class_uid": 4001, "fields_verified": True, "time_source": "device", "sender_ip": "192.0.2.1"}
    return feat.events_frame([{**base, **r} for r in rows])


def test_window_features_are_counted_from_the_events_in_each_window():
    ev = _events([
        {"time": T0 + 1 * MIN, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1", "dst_port": 443, "bytes_out": 100,
         "sequence_num": 1, "device_hostname": "fw1"},
        {"time": T0 + 2 * MIN, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.2", "dst_port": 80, "bytes_out": 50,
         "action_id": 2, "disposition_id": 2, "sequence_num": 2, "device_hostname": "fw1"},
        {"time": T0 + 3 * MIN, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.2", "dst_port": 80, "sequence_num": 3,
         "fields_verified": False, "device_hostname": "fw1"},
        # next window: one old destination, one new; nobody reported bytes
        {"time": T0 + 6 * MIN, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1", "dst_port": 443, "sequence_num": 4},
        {"time": T0 + 7 * MIN, "src_ip": "10.0.0.1", "dst_ip": "198.51.100.9", "dst_port": 443, "sequence_num": 5},
        {"time": T0 + 8 * MIN, "class_uid": 3002, "status_id": 2, "src_ip": "10.0.0.1", "user_name": "bob",
         "sequence_num": 6},
    ])
    f = feat.window_features(ev, "src_ip")
    first, second = f.iloc[0], f.iloc[1]
    assert (first.events, first.denied, first.distinct_dst_ips, first.distinct_dst_ports) == (3, 1, 2, 2)
    assert first.bytes_out == 150 and first.unverified_events == 1 and first.history_windows == 0
    assert (first.first_sequence, first.last_sequence) == (1, 3)
    assert second.events == 3 and second.new_dst_ips == 1 and second.distinct_dst_ips == 2
    assert np.isnan(second.bytes_out)                   # no event said: null, not 0
    assert second.auth_failures == 1 and second.history_windows == 1
    assert first.window_start == "2026-09-21T00:00:00Z" and second.window_end_ms == T0 + 10 * MIN

    users = feat.window_features(ev, "user")
    assert list(users.entity) == ["bob"] and users.iloc[0].auth_failures == 1
    devices = feat.window_features(ev, "device")         # no hostname: known by the address it sent from
    assert set(devices.entity) == {"fw1", "192.0.2.1"}


def test_a_window_is_computed_from_its_own_and_earlier_events_only():
    rng = np.random.default_rng(3)
    rows = [{"time": T0 + int(t), "src_ip": f"10.0.0.{rng.integers(1, 5)}", "dst_ip": f"198.51.100.{rng.integers(1, 40)}",
             "dst_port": int(rng.choice([80, 443, 22])), "bytes_out": int(rng.integers(1, 10_000)), "sequence_num": i}
            for i, t in enumerate(sorted(rng.integers(0, 6 * 60 * MIN, 3000)))]
    cut = T0 + 3 * 60 * MIN
    whole = feat.window_features(_events(rows), "src_ip")
    early = feat.window_features(_events([r for r in rows if r["time"] < cut]), "src_ip")
    before = whole[whole.window_start_ms < cut].reset_index(drop=True)
    pd.testing.assert_frame_equal(before, early)


# --- the baseline --------------------------------------------------------------------------------------

def _history(entity, values, feature="distinct_dst_ports", start=0):
    rows = []
    for k, v in enumerate(values):
        w = T0 + (start + k) * 5 * MIN
        rows.append({"entity_type": "src_ip", "entity": entity, "window_start_ms": w, "window_end_ms": w + 5 * MIN,
                     "events": v, "denied": 0, "distinct_dst_ips": 1, "distinct_dst_ports": 0, "bytes_out": np.nan,
                     "auth_failures": 0, "findings": 0, "first_sequence": k, "last_sequence": k} | {feature: v})
    return rows


def test_a_window_far_above_its_own_history_is_flagged_with_what_it_was_compared_with():
    f = pd.DataFrame(_history("10.0.0.1", [3, 4, 2, 3, 5, 3, 4, 3, 2, 3, 40]))
    result = baseline.score(f, "src_ip")
    (flag,) = result.flags
    (reason,) = flag.reasons
    assert reason.feature == "distinct_dst_ports" and reason.baseline == "own history"
    assert reason.value == 40 and reason.median == 3 and reason.highest == 5 and reason.history == 10
    # deviations from 3: 0,1,1,0,2,0,1,0,1,0 -> MAD 0.5
    assert reason.spread_from == "mad" and reason.robust_z == pytest.approx((40 - 3) / (1.4826 * 0.5))
    assert "40 destination ports in 5 min; its 10 earlier windows: median 3, highest 5, robust z" in flag.summary(5)
    assert flag.title() == "Unusual number of destination ports from 10.0.0.1"
    line = json.loads(flag.line())
    assert "confidence" not in flag.line() and line["reasons"][0]["median"] == 3


def test_nothing_is_flagged_below_the_minimum_increase_however_unusual():
    # 14 ports where there are always 0 is far outside the history, but under the 15-port minimum
    f = pd.DataFrame(_history("10.0.0.1", [0] * 10 + [14]))
    assert baseline.score(f, "src_ip").flags == []
    f = pd.DataFrame(_history("10.0.0.1", [0] * 10 + [15]))
    (flag,) = baseline.score(f, "src_ip").flags
    assert flag.reasons[0].robust_z is None and flag.reasons[0].spread_from == "none"
    assert "median 0, highest 0" in flag.summary(5) and "robust z" not in flag.summary(5)


def test_an_entity_without_history_is_compared_with_its_peers_or_not_scored_at_all():
    peers = []
    for n in range(40):                                  # 40 other sources, 1-3 ports each, earlier
        peers += _history(f"198.51.100.{n}", [1 + n % 3], start=n % 8)
    newcomer = _history("203.0.113.66", [80], start=9)
    result = baseline.score(pd.DataFrame(peers + newcomer), "src_ip", since_ms=T0 + 9 * 5 * MIN)
    (flag,) = result.flags
    assert flag.entity == "203.0.113.66" and flag.reasons[0].baseline == "peers" and flag.reasons[0].history == 40

    lonely = baseline.score(pd.DataFrame(_history("203.0.113.66", [80])), "src_ip")
    assert lonely.flags == [] and lonely.windows_scored == 0 and lonely.windows_without_history == 1


def test_a_flag_has_the_same_id_every_time_it_is_computed():
    f = pd.DataFrame(_history("10.0.0.1", [3, 4, 2, 3, 5, 3, 4, 3, 2, 3, 40]))
    a, b = baseline.score(f, "src_ip").flags[0], baseline.score(f.copy(), "src_ip").flags[0]
    assert a.finding_uid == b.finding_uid and a.line() == b.line()


def test_the_detector_line_is_read_by_its_own_pack_and_nothing_else():
    f = pd.DataFrame(_history("10.0.0.1", [3, 4, 2, 3, 5, 3, 4, 3, 2, 3, 40]))
    line = baseline.score(f, "src_ip").flags[0].line()
    fmt, parsed = parse_log(line)
    assert fmt == "tracelog_baseline" and parsed["_ocsf_class"] == 2004 and parsed["src_ip"] == "10.0.0.1"
    fmt, _ = parse_log(line.replace('"version":1', '"version":2'))
    assert fmt != "tracelog_baseline"                   # an unknown version is not guessed at


def test_the_scheduler_runs_just_after_each_window_closes():
    s = baseline.Schedule(5)
    assert s.GRACE_SECONDS < s._delay() <= 5 * 60 + s.GRACE_SECONDS


# --- end to end ----------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scenario():
    from scripts.synthetic_network import generate
    return generate(seed=7, hours=24, hosts=4)


def test_injected_attacks_become_chained_findings_with_traceable_evidence(isolated_db, scenario):
    from backend.services.integrity.ledger import IntegrityLedger
    from backend.services import jsonio
    from scripts.evaluate_baseline import match

    for i in range(0, len(scenario.lines), 1000):
        ingest([line for _, line in scenario.lines[i:i + 1000]], peer="10.10.0.1")
    events = feat.events_from_db(isolated_db)
    result = baseline.detect(events, since_ms=scenario.start_ms + 2 * 3600 * 1000)
    found = match(result.flags, scenario.attacks)["by_attack"]
    for name in ("fast port sweep", "VPN brute force", "password spray", "exfiltration burst", "lateral SMB scan",
                 "distributed scan"):
        assert found[name], f"{name} was not flagged"
    for name in ("slow port scan", "slow exfiltration"):
        assert not found[name]                          # under the per-window minimum, by design

    stored = baseline.write_findings(result.flags, isolated_db)
    assert len(stored) == len(result.flags)
    for s in stored:
        assert s.format_detected == "tracelog_baseline" and s.normalized["class_uid"] == 2004
        assert validate(s.ocsf) == []
    assert baseline.write_findings(result.flags, isolated_db) == []          # once only
    assert IntegrityLedger.verify_chain().is_valid

    with isolated_db.get_connection() as conn:
        for fl in result.flags:
            assert fl.event_uids
            for uid in fl.event_uids:
                row = conn.execute("SELECT r.raw_text, r.raw_hash FROM normalized_events n JOIN raw_logs r "
                                   "ON r.id = n.raw_id WHERE n.id = ?", (uid,)).fetchone()
                assert hashlib.sha256(row["raw_text"].encode()).hexdigest() == row["raw_hash"]
        n = conn.execute("SELECT COUNT(*) FROM normalized_events WHERE parser_pack = 'tracelog_baseline'").fetchone()[0]
    assert n == len(result.flags)

    # the findings are not fed back into the features
    again = feat.events_from_db(isolated_db)
    assert len(again) == len(events) and "tracelog_baseline" not in set(again["parser"])

    # the live path, an hour at a time, flags exactly what one pass over the day flagged
    for hour in (13, 14):
        until = scenario.start_ms + (hour + 1) * 3600 * 1000
        live = baseline.run(isolated_db, until_ms=until, score_hours=1, write=False)
        batch = {fl.finding_uid for fl in result.flags if until - 3600 * 1000 <= fl.window_start_ms < until}
        assert {f["finding_uid"] for f in live["findings"]} == batch


def test_the_parquet_files_give_the_same_features_as_the_database(isolated_db, tmp_path):
    pytest.importorskip("pyarrow")
    from backend.connectors.config import Output
    from backend.connectors.outputs.file_sinks import ParquetSink

    stored = ingest([FORTI_TRAFFIC, PAN_TRAFFIC, ASA_DENY, FORTI_VPN_FAIL] * 3)
    sink = ParquetSink(Output(name="lake", type="parquet", settings={"root": str(tmp_path / "lake")}),
                       data_dir=str(tmp_path))
    sink.send([s.ocsf for s in stored])
    from_db = feat.all_features(feat.events_from_db(isolated_db))
    from_lake = feat.all_features(feat.events_from_parquet(tmp_path / "lake"))
    cols = [c for c in feat.FEATURE_COLUMNS if c not in ("first_sequence", "last_sequence")]
    pd.testing.assert_frame_equal(from_db[cols].reset_index(drop=True), from_lake[cols].reset_index(drop=True),
                                  check_dtype=False)


def test_the_api_serves_the_contract_the_features_and_a_dry_run(isolated_db):
    import random
    import time

    from backend.main import app
    from scripts.synthetic_network import traffic
    now = int(time.time() * 1000)                       # the endpoint reads the last N hours
    ingest([traffic(now - 60_000, "10.1.1.20", "198.51.100.25", 443, random.Random(1), sent=10, rcvd=20)])
    client = TestClient(app)
    contract = client.get("/api/ml/contract").json()
    assert [c["name"] for c in contract["columns"]] == NAMES
    csv = client.get("/api/ml/features", params={"entity_type": "src_ip", "hours": 1})
    assert csv.status_code == 200 and csv.text.splitlines()[0].split(",") == feat.FEATURE_COLUMNS
    assert "10.1.1.20" in csv.text
    run = client.post("/api/ml/baseline/run", params={"hours": 1, "dry_run": True}).json()
    assert run["findings_written"] == 0 and "windows_scored" in run


def test_the_documented_contract_and_settings_are_the_code():
    from pathlib import Path
    doc = (Path(__file__).resolve().parents[1] / "docs" / "ML_DATA.md").read_text(encoding="utf-8")
    for name, kind, meaning in COLUMNS:
        assert f"| `{name}` | {kind} | {meaning} |" in doc, name
    assert f"at least {baseline.THRESHOLD}" in doc and f"at least {baseline.MIN_OWN_HISTORY};" in doc
    assert f"at least {baseline.MIN_PEER_HISTORY} of those" in doc and f"last {baseline.LOOKBACK_HOURS} hours" in doc
    for entity, minimums in baseline.MIN_EXCESS.items():
        for feature, value in minimums.items():
            shown = "50 MB" if feature == "bytes_out" else f"{value:,}"
            assert f"`{feature}` | {shown} |" in doc, (entity, feature)
