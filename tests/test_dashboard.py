"""
The dashboard: the overview's activity numbers are measured, every page renders, anything that came
from a log line is escaped before it becomes HTML, and the page stays light (no chart library, fonts
served locally, one theme per system setting).
"""
import ast
import re
import sys
from pathlib import Path

import pytest

try:
    import tomllib                  # Python 3.11+
except ModuleNotFoundError:         # Python 3.10: Streamlit brings toml
    import toml as tomllib

from backend.api.analytics import DENIED, _bucket_ms, activity
from backend.services.ingestion.stream import InboundRecord, StreamIngestor
from frontend import ui
from tests.test_vendor_packs import ASA_DENY, FORTI_IPS, FORTI_TRAFFIC, PAN_TRAFFIC, SURICATA

ROOT = Path(__file__).resolve().parents[1]
EVIL = '<img src=x onerror="alert(1)"><script>alert(2)</script>'


def _ingest(lines):
    StreamIngestor().ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="t") for l in lines])


# ------------------------------------------------------------------ what the overview reads
def test_time_slots_are_round_and_about_48_to_a_range():
    assert _bucket_ms(24 * 3_600_000, 48) == 30 * 60_000
    assert _bucket_ms(3_600_000, 48) == 2 * 60_000
    assert _bucket_ms(7 * 24 * 3_600_000, 48) == 6 * 3_600_000


def test_activity_counts_what_is_stored(isolated_db):
    _ingest([FORTI_TRAFFIC, FORTI_TRAFFIC.replace('action="deny"', 'action="accept"'), FORTI_IPS, PAN_TRAFFIC,
             ASA_DENY, SURICATA])
    with isolated_db.get_connection() as conn:
        rows = conn.execute("SELECT time_epoch_ms, disposition, class_uid FROM normalized_events "
                            "WHERE superseded_by IS NULL").fetchall()
    newest = max(r[0] for r in rows)

    act = activity(hours=0)
    timeline, totals, window = act["timeline"], act["totals"], act["window"]
    assert window["to_ms"] == newest and act["events"] == len(rows)
    assert sum(p["events"] for p in timeline) == totals["events"] == len(rows)
    assert sum(p["denied"] for p in timeline) == totals["denied"] == sum(1 for r in rows if r[1] in DENIED)
    steps = {b["t"] - a["t"] for a, b in zip(timeline, timeline[1:])}
    assert steps <= {window["bucket_ms"]} and all(p["t"] % window["bucket_ms"] == 0 for p in timeline)
    findings = [r for r in rows if r[2] == 2004]
    assert totals["findings"] == len(findings) == len(act["findings"]) == sum(s["events"] for s in act["findings_by_severity"])
    assert "MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution" in {f["title"] for f in act["findings"]}
    assert sum(s["events"] for s in act["by_source"]) == sum(c["events"] for c in act["by_class"]) == len(rows)

    narrow = activity(hours=0.01)                   # the newest 36 seconds only
    assert narrow["totals"]["events"] == sum(1 for r in rows if r[0] >= newest - 36_000)


def test_activity_of_an_empty_archive(isolated_db):
    act = activity(hours=24)
    assert act["events"] == 0 and act["timeline"] == [] and act["window"] is None


# ------------------------------------------------------------------ every page renders
@pytest.fixture
def dashboard(isolated_db, monkeypatch):
    """Direct mode (no API answering) over isolated_db's file, with sample data in it."""
    from backend.config import settings
    from backend.services.storage.db import Database
    from frontend import api_client
    for name, module in list(sys.modules.items()):
        if name.startswith("backend.") and isinstance(getattr(module, "db", None), Database):
            monkeypatch.setattr(module, "db", isolated_db)
    monkeypatch.setattr(api_client, "BASE_URL", "http://127.0.0.1:9/api")      # nothing listens there
    monkeypatch.setattr(settings, "BACKEND_PORT", 9)
    monkeypatch.setattr(settings, "DASHBOARD_DIRECT_MODE", True)
    _ingest([FORTI_TRAFFIC, FORTI_IPS, PAN_TRAFFIC, ASA_DENY, SURICATA])
    return isolated_db


PAGES = ["overview_page:render_overview", "sources_page:render_sources", "parser_studio_page:render_parser_studio",
         "pipeline_page:render_pipeline", "explorer_page:render_explorer", "integrity_page:render_integrity",
         "correlation_page:render_correlation", "schema_page:render_schema",
         "integrations_page:render_integrations", "settings_page:render_settings"]


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_without_an_error(dashboard, page):
    from streamlit.testing.v1 import AppTest
    module, func = page.split(":")
    at = AppTest.from_string(f"from frontend import ui\nui.apply_theme()\n"
                             f"from frontend.views.{module} import {func}\n{func}()\n", default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]


# ------------------------------------------------------------------ log text never becomes markup
def test_log_text_is_escaped_in_every_chart():
    outputs = [
        ui.bar_list([(EVIL, 5), ("ok", 3)]),
        ui.bar_list([(EVIL, 5)], mono=True),
        ui.parts([(EVIL, 5), ("b", 1)]),
        ui.kpi(EVIL, "1"),
        ui.tile(EVIL, ""),
        ui.table([(EVIL, "")], [[f"<td>{ui.esc(EVIL)}</td>"]]),
        ui.timeseries([{"t": 0, "events": 3, "denied": 1}, {"t": 60_000, "events": 2, "denied": 0}], 60_000,
                      {0: {"count": 1, "worst": "high", "titles": [EVIL]}}),
        ui.lanes([(EVIL, [{"t": 1_000, "severity_id": 4, "title": EVIL, "detail": EVIL}])], 0, 2_000),
        ui.sev_tag(4, EVIL),
        ui.status_block(False, False, EVIL, 8000),
        ui.legend([(EVIL, "c1", "line")]),
    ]
    for html in outputs:
        assert "<img" not in html and "<script" not in html and "onerror=\"" not in html, html[:300]
        assert "&lt;img" in html or "&lt;script" in html


def test_numbers_read_as_people_write_them():
    assert (ui.compact(32311), ui.compact(1_500_000), ui.compact(950), ui.compact(100_000)) == ("32.3K", "1.5M", "950", "100K")
    assert (ui.pct(99.5), ui.pct(100), ui.pct(0)) == ("99.5%", "100%", "0%")
    assert ui.utc(1789986000000, "%d %b %H:%M") == "21 Sep 10:20" and ui.utc(1789986000000, "%H:%M") == "10:20"


# ------------------------------------------------------------------ a light page, one look per system setting
def test_the_dashboard_loads_no_chart_library():
    heavy = {"plotly", "altair", "matplotlib", "bokeh", "pydeck", "vega_datasets"}
    for path in (ROOT / "frontend").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert not names & heavy, f"{path.name} imports {names & heavy}"
        assert "st.plotly_chart" not in path.read_text(encoding="utf-8")
    assert "plotly" not in (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_light_and_dark_themes_follow_the_system_with_local_fonts():
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    theme = config["theme"]
    assert "base" not in theme                                  # no forced light or dark
    assert set(theme["light"]) - {"sidebar"} == set(theme["dark"]) - {"sidebar"}
    assert config["server"]["enableStaticServing"] is True
    for face in theme["fontFaces"]:
        assert face["url"].startswith("app/static/")             # served by the dashboard, not a font host
        assert (ROOT / "frontend" / "static" / face["url"][len("app/static/"):]).is_file(), face["url"]
    assert (ROOT / "frontend" / "static" / "fonts" / "OFL.txt").is_file()
    css = (ROOT / "frontend" / "assets" / "theme.css").read_text(encoding="utf-8")
    assert "@media (prefers-color-scheme: dark)" in css and "prefers-reduced-transparency" in css
    assert not re.search(r"@import|url\(\s*['\"]?https?:", css)   # nothing fetched from outside


def test_page_names_are_plain():
    app = (ROOT / "frontend" / "app.py").read_text(encoding="utf-8")
    titles = re.findall(r'st\.Page\([^)]*?title="([^"]+)"', app)
    assert len(titles) == 10 and not [t for t in titles if "&" in t or "(" in t]
