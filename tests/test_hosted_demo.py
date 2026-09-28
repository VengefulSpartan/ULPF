"""Hosted demo (backend/hosted_demo.py): the API and two witnesses started inside the dashboard's process."""
import socket

import pytest
import requests

from backend.config import settings
from backend.services.integrity import signing


def _free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def test_off_unless_asked():
    from backend.config import Settings
    assert Settings.model_fields["HOSTED_DEMO"].default is False


def test_sidebar_says_it_is_a_hosted_demo():
    from frontend import ui
    assert "hosted demo, inside this app" in ui.status_block(True, True, "127.0.0.1", 8000, hosted={"data": "loaded"})
    assert "loading the demo data" in ui.status_block(True, True, "127.0.0.1", 8000, hosted={"data": "loading"})
    assert "127.0.0.1:8000" in ui.status_block(True, True, "127.0.0.1", 8000)
    failed = ui.status_block(False, True, "127.0.0.1", 8000, hosted={"error": "RuntimeError: the API did not start"})
    assert "Hosted demo: API not running" in failed and "the API did not start" in failed


@pytest.mark.skipif(not signing.HAVE_CRYPTO, reason="signed checkpoints need cryptography")
def test_starts_the_api_and_two_witnesses_that_countersign(isolated_db, tmp_path, monkeypatch):
    from backend import hosted_demo

    config = tmp_path / "tracelog.yaml"   # no syslog listener: the tests' ports are not ours to take
    config.write_text("tracelog:\n  inputs:\n    http: {enabled: true}\n  outputs: []\n", encoding="utf-8")
    monkeypatch.setenv("TRACELOG_CONFIG", str(config))
    monkeypatch.setattr(settings, "DB_PATH", isolated_db.db_path)
    monkeypatch.setattr(settings, "TRACELOG_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(settings, "WITNESS_URLS", "")
    monkeypatch.setattr(settings, "CHECKPOINT_EVERY_SECONDS", 0)
    api_port, w1, w2 = _free_ports(3)
    try:
        state = hosted_demo.start(seed=False, api_port=api_port, witness_ports=(w1, w2))
        assert state["error"] is None and state["api"] == f"http://127.0.0.1:{api_port}"
        assert requests.get(f"{state['api']}/health", timeout=5).status_code == 200
        assert settings.WITNESS_URLS == f"http://127.0.0.1:{w1},http://127.0.0.1:{w2}"
        assert (tmp_path / "witness-1" / "witness.db").exists()   # beside the database, like run_app.py

        servers = len(hosted_demo._servers)
        assert hosted_demo.start(seed=False, api_port=api_port, witness_ports=(w1, w2)) is state
        assert len(hosted_demo._servers) == servers == 3   # once per process

        # the demo data, without the synthetic day (32,000 lines) to keep the test short
        sent = hosted_demo.load_demo_data(state["api"], synthetic=False)
        assert sent["samples"] > 0 and sent.get("watchguard") == 150
        v = requests.get(f"{state['api']}/api/integrity/checkpoints", timeout=60).json()
        assert v["ok"], v["problems"]
        assert v["checkpoints"] >= 1 and v["unsealed_records"] == 0 and v["head_seq"] == v["sealed_records"]
        assert [w["agree"] for w in v["witnesses"]] == [v["checkpoints"]] * 2
    finally:
        hosted_demo.stop()
    assert not hosted_demo.STATE["started"]


def test_a_failure_leaves_the_dashboard_in_direct_mode(monkeypatch):
    from backend import hosted_demo

    def refuse(*_a, **_k):
        raise RuntimeError("the API did not start on http://127.0.0.1:1")

    monkeypatch.setattr(hosted_demo, "_serve", refuse)
    monkeypatch.setattr(settings, "WITNESS_URLS", "http://witness.example:8000")   # nothing of ours to start
    try:
        state = hosted_demo.start(seed=False)
        assert not state["started"] and "did not start" in state["error"]
    finally:
        hosted_demo.stop()
