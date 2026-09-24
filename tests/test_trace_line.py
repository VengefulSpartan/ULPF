"""
docs/END_TO_END_FLOW.md follows one FortiGate line through TRACELOG, quoting what
scripts/trace_line.py prints. This keeps the two in step: if a stage stops producing what the
document shows, this fails.
"""
import sys

RAW_SHA256 = "3150bb1390e5e004b4dbc3b47d8bda43f39764c9d956889ff20f74b39c83595a"   # quoted in the document


def test_the_documented_line_goes_through_every_stage(isolated_db, monkeypatch, capsys):
    import scripts.benchmark as bench
    import scripts.trace_line as trace
    monkeypatch.setattr(bench, "setup_database", lambda path: isolated_db)
    monkeypatch.setattr(sys, "argv", ["trace_line.py"])
    trace.main()
    out = capsys.readouterr().out
    assert "parser: fortinet_fortigate" in out
    assert out.count(RAW_SHA256) >= 3                      # stored, recomputed, carried in the OCSF labels
    assert "raw_text.encode(raw_encoding) == bytes received: True" in out
    assert '"name": "Fortinet FortiGate (FGT-HQ)"' in out
    assert '"time": 1789986000000' in out                  # 15:50 at +05:30 is 10:20 UTC
    assert "matches: True" in out
    assert "POST https://splunk.example:8088/services/collector/event" in out
    assert "CEF:0|TRACELOG|TRACELOG|1.0|400105|Network Activity: Refuse|3|" in out
    assert "event chain valid: True" in out and "delivery ledger valid: True" in out
