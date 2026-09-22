"""
What the dashboard and exports show must be measured, and what they hand out must be valid:
no constant accuracy figures, OCSF exports that pass OCSF checks, sample data with the right
dates, and product naming that matches the docs.
"""
import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.services.normalization.ocsf_export import validate
from backend.services.parsing.dispatch import parse_log
from tests.unseen_corpus import CORPUS

PAN_OR_ASA = '<166>Sep 20 14:00:15 ciscoasa %ASA-6-302013: Built inbound TCP connection 88123 for ' \
             'outside:198.51.100.22/51200 to inside:10.0.1.15/443'
UNKNOWN = "something nobody parses: kernel ring buffer said hello"


def _client():
    from backend.main import app
    return TestClient(app)


def test_overview_numbers_are_measured(isolated_db):
    from backend.services.ingestion.pipeline import IngestionPipeline
    from backend.api.sources import create_source, SourceCreate
    src = create_source(SourceCreate(name="t", vendor="Cisco", product="ASA", format_type="syslog"))
    for line in (PAN_OR_ASA, UNKNOWN, UNKNOWN + " again"):
        IngestionPipeline.ingest_single_log(line, src.id)
    from backend.api.analytics import get_overview_kpis
    k = get_overview_kpis()
    assert k["parsing"]["vendor_pack"] == 1 and k["parsing"]["generic"] == 2
    assert k["parser_success_rate"] == 33.3                      # 1 of 3 read by a known parser, not "99.4"
    assert k["ocsf_conformance"]["checked"] == 3 and k["normalization_success_rate"] == 100.0
    assert k["pipeline"]["consistent"] and k["pipeline"]["raw_archived"] == 3


def test_ocsf_export_is_valid_ocsf(isolated_db):
    client = _client()
    assert client.post("/api/ingest/seed-samples").status_code == 200
    events = client.get("/api/export/ocsf-json").json()
    assert events and all(validate(e) == [] for e in events)
    assert all(isinstance(e["time"], int) for e in events)       # epoch milliseconds, as OCSF requires


def test_yearless_syslog_timestamps_get_this_year():
    _, parsed = parse_log(PAN_OR_ASA)
    year = int(parsed["timestamp"][:4])
    now = datetime.now(timezone.utc).year
    assert year in (now, now - 1) and parsed["timestamp"][5:19] == "09-20T14:00:15"


def test_cef_is_a_standard_format_not_a_new_one():
    fmt, parsed = parse_log("CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 "
                            "spt=49152 dpt=445 proto=TCP act=allow")
    assert fmt == "generic_cef" and parsed["src_ip"] == "10.0.1.15"
    assert parsed["tracelog_parse"]["verified"] and parsed["tracelog_parse"]["standard"] == "CEF"


def test_traffic_without_direction_is_network_activity_with_empty_endpoints():
    watchguard = next(c for c in CORPUS if c["name"].startswith("WatchGuard"))
    _, parsed = parse_log(watchguard["line"])
    assert parsed["_ocsf_class"] == 4001 and "src_ip" not in parsed and "dst_ip" not in parsed
    assert len(parsed["tracelog_parse"]["unassigned_ips"]) == 2


def test_health_names_the_product():
    body = _client().get("/health").json()
    assert body["status"] == "healthy" and body["service"] == "TRACELOG API"
    assert "TRACELOG" in json.dumps(_client().get("/openapi.json").json()["info"])
