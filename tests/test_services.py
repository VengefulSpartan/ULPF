"""
TRACELOG as services (docs/SERVICES.md, docker-compose.yml): what each one may do.

- only the collector writes; the query service and the detector open the database read-only;
- the gateway sends each request to the service that answers it, and a read to the query service
  only when the query service really serves that route;
- the detector's findings reach the chain through the collector, once each;
- the dashboard never becomes a second writer when the API is down.
"""
import json
import re
import sqlite3
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.main import QUERY_ROUTERS, create_app
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from backend.services.ml import baseline
from backend.services.storage.db import Database
from tests.test_vendor_packs import ASA_DENY, FORTI_TRAFFIC, PAN_TRAFFIC

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
READ_PATHS = ["/api/events", "/api/events?q=10.20.4.5", "/api/integrity/verify", "/api/integrity/ledger",
              "/api/analytics/overview", "/api/analytics/unparsed", "/api/export/csv", "/api/export/ocsf-json",
              "/api/audit/reconcile", "/api/audit/report.json", "/api/audit/delivery/verify",
              "/api/correlation/incidents", "/api/ml/contract", "/api/ml/features?hours=48", "/api/formats",
              "/api/sources", "/api/parsers", "/api/analytics/activity?hours=24",
              "/api/integrity/checkpoints?witnesses=false", "/api/evidence/bundle.zip?seq=1&seq=2",
              "/api/compliance/certin/status"]


def routes(app):
    """(METHOD, path) for every route in the app's OpenAPI schema."""
    return {(m.upper(), path) for path, ops in app.openapi()["paths"].items() for m in ops}


def gateway():
    """The gateway's routing, read from docker/gateway/nginx.conf: (METHOD, path) -> service."""
    text = (ROOT / "docker" / "gateway" / "nginx.conf").read_text(encoding="utf-8")
    block = re.search(r'map "\$request_method \$uri" \$tracelog_service \{(.*?)\n\s*\}', text, re.S).group(1)
    default = re.search(r"^\s*default\s+(\S+);", block, re.M).group(1)
    rules = [(re.compile(m.group(1)), m.group(2)) for m in re.finditer(r'"~(.+?)"\s+(\S+);', block)]

    def route(method: str, path: str) -> str:
        for rx, service in rules:           # nginx tries the regexes in order; the first match wins
            if rx.search(f"{method} {path}"):
                return service
        return default
    return route


# ------------------------------------------------------------------ what each service serves
def test_the_query_service_serves_reads_only():
    query, everything = routes(create_app("query")), routes(create_app("all"))
    assert query and all(method == "GET" for method, _ in query)
    assert query <= everything
    assert {p.split("/")[2] for _, p in query if p.startswith("/api/")} == {p.strip("/") for p in QUERY_ROUTERS}
    client = TestClient(create_app("query"))
    assert client.post("/api/ingest/single", json={}).status_code == 404
    assert client.post("/services/collector/raw", content=b"x").status_code == 404
    assert client.get("/api/connectors").status_code == 404   # the collector's live state
    assert client.get("/health").json()["role"] == "query"


def test_the_gateway_sends_every_route_to_the_service_that_has_it():
    route, query = gateway(), routes(create_app("query"))
    for method, path in sorted(routes(create_app("all"))):
        concrete = re.sub(r"\{[^}]+\}", "x", path)
        # the query service's own /health and /docs are for its container, not for the outside
        expected = "query" if (method, path) in query and path.startswith("/api/") else "collector"
        assert route(method, concrete) == expected, f"{method} {path}"
    assert route("GET", "/health") == "collector" and route("GET", "/docs") == "collector"
    assert route("GET", "/api/eventsX") == "collector"         # prefixes end at a /, not mid-word


# ------------------------------------------------------------------ read-only database
def test_a_read_only_database_refuses_every_write(tmp_path):
    writer = Database(tmp_path / "t.db")
    reader = Database(tmp_path / "t.db", read_only=True)
    assert reader.get_connection().execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        with reader.get_connection() as conn:
            conn.execute("DELETE FROM integrity_ledger")
    writer.close()
    with pytest.raises(sqlite3.OperationalError, match="collector creates it"):
        Database(tmp_path / "missing.db", read_only=True).get_connection()
    assert not (tmp_path / "missing.db").exists()


@pytest.fixture
def query_view(isolated_db, monkeypatch):
    """The query service over isolated_db's file: every module that uses the database gets a read-only one."""
    StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t")
                             for l in (PAN_TRAFFIC, FORTI_TRAFFIC, ASA_DENY) * 5])
    reader = Database(isolated_db.db_path, read_only=True)
    import backend.services.integrity.ledger as ledger_module
    import backend.services.storage.db as db_module
    monkeypatch.setattr(db_module, "db", reader)
    monkeypatch.setattr(ledger_module, "db", reader)
    for mod in ("backend.api.connectors", "backend.api.sources", "backend.api.events", "backend.api.integrity",
                "backend.api.parsers", "backend.api.analytics", "backend.api.export", "backend.api.ingestion",
                "backend.services.ingestion.pipeline"):
        m = __import__(mod, fromlist=["db"])
        if hasattr(m, "db"):
            monkeypatch.setattr(m, "db", reader)
    return TestClient(create_app("query"))


def _counts(path):
    conn = sqlite3.connect(path)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    counts = {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
    conn.close()
    return counts


def test_every_query_route_answers_from_a_read_only_database(query_view, isolated_db):
    before = _counts(isolated_db.db_path)
    for path in READ_PATHS:
        r = query_view.get(path)
        assert r.status_code == 200, f"{path}: {r.text[:300]}"
    assert query_view.get("/api/integrity/verify").json()["is_valid"] is True
    assert _counts(isolated_db.db_path) == before


# ------------------------------------------------------------------ the detector writes through the collector
def _flag(entity="203.0.113.66", start=1_789_984_800_000):
    reason = baseline.Reason(feature="distinct_dst_ports", value=80, median=2, highest=4, spread=1,
                             spread_from="mad", robust_z=52.6, history=40, baseline="own history", min_excess=20)
    return baseline.Flag("src_ip", entity, start, start + 300_000, [reason], events=80)


def test_the_collector_writes_the_detectors_findings_once(isolated_db):
    client = TestClient(create_app("collector"))
    body = {"findings": [{"uid": f.finding_uid, "line": f.line()} for f in (_flag(), _flag("192.0.2.77"))]}
    first = client.post("/api/ml/findings", json=body).json()
    again = client.post("/api/ml/findings", json=body).json()
    assert (first["written"], again["written"]) == (2, 0) and len(first["sequence_nums"]) == 2
    with isolated_db.get_connection() as conn:
        rows = conn.execute("SELECT class_name FROM normalized_events WHERE parser_pack = 'tracelog_baseline'").fetchall()
    assert [r[0] for r in rows] == ["Detection Finding", "Detection Finding"]


def test_the_findings_intake_needs_the_token_when_the_collector_requires_one(isolated_db, monkeypatch):
    from backend.connectors.engine import engine
    monkeypatch.setattr(engine.config.inputs.http, "tokens", ["s3cret"])
    client = TestClient(create_app("collector"))
    body = {"findings": [{"uid": _flag().finding_uid, "line": _flag().line()}]}
    assert client.post("/api/ml/findings", json=body).status_code == 401
    ok = client.post("/api/ml/findings", json=body, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200 and ok.json()["written"] == 1


def test_the_detector_service_sends_its_flags_to_the_collector(mock_http):
    from backend.services.ml.worker import CollectorWriter
    mock_http.responses["/api/ml/findings"] = (200, {"received": 1, "written": 1, "sequence_nums": [42]})
    written = CollectorWriter(mock_http.url, token="s3cret")([_flag()], None, 5)
    request = mock_http.requests[-1]
    assert written == [42] and request["method"] == "POST"
    assert request["headers"]["Authorization"] == "Bearer s3cret"
    sent = json.loads(request["body"])["findings"]
    assert sent == [{"uid": _flag().finding_uid, "line": _flag().line(5)}]
    assert CollectorWriter(mock_http.url)([], None, 5) == []       # nothing to send, no request


# ------------------------------------------------------------------ the dashboard is never a second writer
def test_the_dashboard_says_the_api_is_down_instead_of_writing(monkeypatch):
    from backend.config import settings
    from frontend import api_client
    monkeypatch.setattr(api_client, "BASE_URL", "http://127.0.0.1:9/api")      # nothing listens there
    monkeypatch.setattr(settings, "DASHBOARD_DIRECT_MODE", False)
    with pytest.raises(api_client.BackendUnreachable):
        api_client.APIClient.seed_samples()                      # would have written sample events here
    assert "did not answer" in api_client.APIClient.format_detail("x")["error"]


def test_the_settings_page_does_not_open_the_database_when_it_loads():
    import ast
    tree = ast.parse((ROOT / "frontend" / "views" / "settings_page.py").read_text(encoding="utf-8"))
    top_level = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert not [n for n in top_level if getattr(n, "module", "") == "backend.services.storage.db"]


# ------------------------------------------------------------------ docker-compose.yml
def _env(service):
    env = SERVICES[service].get("environment") or {}
    return env if isinstance(env, dict) else dict(e.split("=", 1) for e in env)


def test_one_writer_and_readers_that_cannot_write():
    assert _env("collector")["SERVICE_ROLE"] == "collector"
    assert _env("query")["SERVICE_ROLE"] == "query" and _env("query")["DB_READ_ONLY"] == "true"
    assert _env("detector")["DB_READ_ONLY"] == "true" and _env("detector")["COLLECTOR_URL"] == "http://collector:8000"
    assert _env("dashboard")["DASHBOARD_DIRECT_MODE"] == "false" and _env("dashboard")["BACKEND_HOST"] == "gateway"
    assert "volumes" not in SERVICES["dashboard"]                  # the dashboard has no database at all
    for name in ("collector", "query", "detector"):
        data = [v for v in SERVICES[name]["volumes"] if v.endswith(":/app/data")]
        assert data == ["tracelog-data:/app/data"], name           # a named volume, never a host folder


def test_only_the_gateway_and_the_collector_face_the_network():
    published = {name: [str(p) for p in svc.get("ports", [])] for name, svc in SERVICES.items()
                 if "sensor" not in svc.get("profiles", [])}
    assert published["gateway"] == ["8000:8000"]
    assert all(p.split(":")[1].startswith(("5514", "6514")) for p in published["collector"])
    assert published["dashboard"] == ["8501:8501"]
    assert not published["query"] and not published["detector"] and not published["tests"]
    assert SERVICES["tests"]["network_mode"] == "none"
    assert "./docker/gateway/nginx.conf:/etc/nginx/nginx.conf:ro" in SERVICES["gateway"]["volumes"]


def test_the_test_image_keeps_secrets_and_data_out():
    rules = {l.strip() for l in (ROOT / "docker" / "tests.Dockerfile.dockerignore").read_text(encoding="utf-8")
             .splitlines() if l.strip() and not l.startswith("#")}
    assert {".env", ".env.*", "data/*", ".git/", "results/", "Project outputs/"} <= rules
    assert not {"tests/", "docs/", "*.md", ".gitattributes"} & rules        # the tests read these
    dockerfile = (ROOT / "docker" / "tests.Dockerfile").read_text(encoding="utf-8")
    assert "USER tracelog" in dockerfile and "python:3.11-slim" in dockerfile
