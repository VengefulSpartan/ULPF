"""
PS item (j): deployable in an air-gapped network. Nothing TRACELOG serves may depend on reaching
the internet, and nothing may report home. Checked without a network here; the full check (both
servers in a network namespace with no route out, pages loaded in a browser, every request
recorded) is described in docs/AIRGAP.md.
"""
import hashlib
import re
import tomllib
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "backend" / "static" / "swagger-ui"


def test_dashboard_sends_no_usage_statistics():
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text())
    assert config["browser"]["gatherUsageStats"] is False


def test_api_docs_load_nothing_from_outside():
    client = TestClient(app)
    html = client.get("/docs").text
    assert re.findall(r'(?:src|href)="([^"]+)"', html) and all(
        u.startswith("/") for u in re.findall(r'(?:src|href)="([^"]+)"', html))
    assert '"validatorUrl": null' in html
    for asset in ("swagger-ui-bundle.js", "swagger-ui.css", "favicon-32x32.png"):
        assert client.get(f"/static/swagger-ui/{asset}").status_code == 200


def test_swagger_ui_files_are_the_pinned_upstream_files():
    recorded = dict(reversed(line.split()) for line in (SWAGGER / "VERSION.txt").read_text().splitlines()
                    if re.fullmatch(r"[0-9a-f]{64}  \S+", line))
    assert recorded
    for name, digest in recorded.items():
        assert hashlib.sha256((SWAGGER / name).read_bytes()).hexdigest() == digest, name


def test_no_page_or_service_pulls_from_a_cdn_or_font_host():
    hosts = re.compile(r"cdn\.jsdelivr|unpkg\.com|cdnjs\.|fonts\.googleapis|fonts\.gstatic|googletagmanager")
    offenders = [str(p.relative_to(ROOT)) for folder in ("backend", "frontend")
                 for p in (ROOT / folder).rglob("*.py") if hosts.search(p.read_text(encoding="utf-8"))]
    assert offenders == []

