"""
scripts/run_all_checks.py is how numbers get measured on another machine, so its reading of each
script's output and its comparison of two machines must be right. The checks themselves are
tested elsewhere; this tests the runner's own logic on recorded outputs.
"""
import json

from scripts.run_all_checks import _json_tail, compare, summary_md

MACHINE = {"hostname": "old", "cpu": "Old CPU", "physical_cores": 2, "logical_cpus": 4, "memory_gb": 8,
           "os": "Linux", "wsl": False, "python": "3.12.3", "sqlite": "3.45.1", "on_mains_power": True,
           "cpu_governor": None, "docker": None, "packages": {"pandas": "3.0.6"}, "repo_on_windows_drive": False,
           "git_commit": "abc1234", "git_uncommitted_files": 0}


def _results(rate, dashboard, tests="PASS"):
    return [
        {"name": "Test suite (pytest)", "kind": "claim", "status": tests, "result": "302 passed", "seconds": 40, "data": {}},
        {"name": "Throughput, one process", "kind": "measurement", "status": "MEASURED", "result": f"{rate} events/s",
         "seconds": 60, "data": {"events_per_second_median": rate, "batch_ms_p50_median": 400.0,
                                 "read_ms_median": {"dashboard_ms": dashboard}}},
        {"name": "Throughput, sharded", "kind": "measurement", "status": "MEASURED", "result": "", "seconds": 30,
         "data": {"runs": [{"shards": 2, "events_per_second": rate * 2, "per_shard_average": rate,
                            "speedup_vs_one_process": 2.0, "per_day_millions": 1.0}]}},
    ]


def test_json_is_read_after_progress_lines():
    assert _json_tail("seed 1: 11 flags\nreport: x\n[\n {\"seed\": 1}\n]\n") == [{"seed": 1}]


def test_the_summary_names_the_machine_and_every_failure():
    text = summary_md(MACHINE, _results(2000, 150.0, tests="FAIL"), "2026-09-26 10:00", 120)
    assert "| CPU | Old CPU |" in text and "| Test suite (pytest) | FAIL |" in text
    assert "did not hold" in text and "Test suite (pytest)" in text.split("## Verdict")[1]
    assert "| 2 | 4,000 | 2,000 | 2.0x | 1.0 |" in text


def test_two_machines_are_compared_metric_by_metric(tmp_path):
    for name, rate, dash in (("old", 2000, 150.0), ("new", 5000, 60.0)):
        d = tmp_path / name
        d.mkdir()
        (d / "summary.json").write_text(json.dumps({"machine": {**MACHINE, "hostname": name},
                                                    "results": _results(rate, dash)}))
    text = compare(tmp_path / "old", tmp_path / "new")
    assert "| Throughput, one process (events/s, median) | 2000 | 5000 | 2.50x |" in text
    assert "| Dashboard figures (ms) | 150.0 | 60.0 | 0.40x |" in text
    assert "| 2 shards (events/s) | 4000 | 10000 | 2.50x |" in text
    assert "| Test suite (pytest) | PASS | PASS | |" in text
