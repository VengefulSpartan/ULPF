#!/usr/bin/env python3
"""
Run every check TRACELOG has, on this machine, and write down what it measured.

    python scripts/run_all_checks.py                  # everything: about 15-25 minutes
    python scripts/run_all_checks.py --quick          # smaller runs, no public samples, no image build
    python scripts/run_all_checks.py --skip container,public
    python scripts/run_all_checks.py --compare results/old-laptop-... results/new-laptop-...

Each run writes a folder under results/ (git-ignored), named after the machine and the time:

    machine.json          CPU, cores, memory, OS, Python, package versions, git commit
    <check>.log / .json   the raw output of every check, exactly as the script printed it
    PUBLIC_SAMPLES.md     the real-log report, as scripts/evaluate_public_samples.py writes it
    ML_EVALUATION.md      the detector report, as scripts/evaluate_baseline.py writes it
    summary.md            one page: what each check measured, and whether it passed
    summary.json          the same, for --compare

A check that is a claim (0 wrong fields, 0 invalid OCSF events, the chain verifies) is marked PASS
or FAIL against that claim. A check that is a measurement (events per second) is not pass or fail:
it is recorded with the hardware beside it, the median of --repeat runs, and the spread between
them, because one run on a laptop is not a number anyone should quote.

Nothing here changes the TRACELOG database: every check uses a throwaway one. The docs are not
rewritten either; reports go into the results folder.
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PY = sys.executable
BILLION_PER_DAY = 1_000_000_000 / 86_400        # 11,574 events/s


# ---------------------------------------------------------------------------------------------------------
# the machine
# ---------------------------------------------------------------------------------------------------------
def _run_text(cmd: List[str]) -> str:
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def machine() -> Dict[str, Any]:
    info: Dict[str, Any] = {"hostname": socket.gethostname(), "os": platform.platform(),
                            "kernel": platform.release(), "python": platform.python_version(),
                            "logical_cpus": os.cpu_count()}
    info["wsl"] = "microsoft" in platform.release().lower()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        text = cpuinfo.read_text(errors="replace")
        m = re.search(r"^model name\s*:\s*(.+)$", text, re.M)
        info["cpu"] = m.group(1).strip() if m else platform.processor()
        cores = {(p, c) for p, c in re.findall(r"physical id\s*:\s*(\d+).*?core id\s*:\s*(\d+)", text, re.S)}
        info["physical_cores"] = len(cores) or None
    elif sys.platform == "darwin":
        info["cpu"] = _run_text(["sysctl", "-n", "machdep.cpu.brand_string"])
        info["physical_cores"] = int(_run_text(["sysctl", "-n", "hw.physicalcpu"]) or 0) or None
    else:
        info["cpu"] = platform.processor()
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        m = re.search(r"MemTotal:\s*(\d+) kB", meminfo.read_text())
        info["memory_gb"] = round(int(m.group(1)) / 1024 / 1024, 1) if m else None
    elif sys.platform == "darwin":
        info["memory_gb"] = round(int(_run_text(["sysctl", "-n", "hw.memsize"]) or 0) / 1024 ** 3, 1)
    ac = list(Path("/sys/class/power_supply").glob("A*/online")) if Path("/sys/class/power_supply").exists() else []
    info["on_mains_power"] = (ac[0].read_text().strip() == "1") if ac else None
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    info["cpu_governor"] = gov.read_text().strip() if gov.exists() else None
    info["repo_on_windows_drive"] = str(ROOT).startswith("/mnt/")
    info["git_commit"] = _run_text(["git", "rev-parse", "--short", "HEAD"])
    info["git_uncommitted_files"] = len([l for l in _run_text(["git", "status", "--porcelain"]).splitlines() if l])
    import sqlite3
    info["sqlite"] = sqlite3.sqlite_version
    versions = {}
    for pkg in ("fastapi", "pydantic", "pandas", "numpy", "pyarrow", "orjson", "streamlit", "pytest"):
        try:
            versions[pkg] = __import__(pkg).__version__
        except Exception:
            versions[pkg] = None
    info["packages"] = versions
    info["docker"] = _run_text(["docker", "version", "--format", "{{.Server.Version}}"]) if shutil.which("docker") else None
    return info


# ---------------------------------------------------------------------------------------------------------
# running one check
# ---------------------------------------------------------------------------------------------------------
class Check:
    def __init__(self, out: Path):
        self.out = out
        self.results: List[Dict[str, Any]] = []

    def run(self, name: str, cmd: List[str], log: str, timeout: int, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        shown = " ".join("python" if part == PY else part for part in cmd)
        print(f"  running {name}: {shown}", flush=True)
        t0 = time.perf_counter()
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                               env={**os.environ, **(env or {})})
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = -1, exc.stdout or "", f"timed out after {timeout} s"
            stdout = stdout.decode() if isinstance(stdout, bytes) else stdout
        seconds = round(time.perf_counter() - t0, 1)
        (self.out / log).write_text(stdout + ("\n--- stderr ---\n" + stderr if stderr.strip() else ""),
                                    encoding="utf-8")
        return {"code": code, "stdout": stdout, "stderr": stderr, "seconds": seconds}

    def record(self, name: str, kind: str, status: str, result: str, seconds: float, data: Dict[str, Any]) -> None:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "MEASURED": "measured", "SKIPPED": "skipped"}[status]
        print(f"  {mark:8} {name}: {result}", flush=True)
        self.results.append({"name": name, "kind": kind, "status": status, "result": result, "seconds": seconds,
                             "data": data})


def _json_tail(text: str) -> Any:
    """The JSON a script printed after any progress lines."""
    for i, line in enumerate(text.splitlines()):
        if line.startswith(("{", "[")):
            try:
                return json.loads("\n".join(text.splitlines()[i:]))
            except ValueError:
                continue
    raise ValueError("no JSON in the output")


# ---------------------------------------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------------------------------------
def check_tests(c: Check, quick: bool) -> None:
    r = c.run("tests", [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], "pytest.log", 1800)
    tail = [l for l in r["stdout"].splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    counts = {k: int(v) for v, k in re.findall(r"(\d+) (passed|failed|skipped|errors?|xfailed)", tail[-1])} if tail else {}
    ok = r["code"] == 0 and counts.get("failed", 0) == 0 and not counts.get("error") and not counts.get("errors")
    skipped = counts.get("skipped", 0)
    c.record("Test suite (pytest)", "claim", "PASS" if ok else "FAIL",
             f"{counts.get('passed', 0)} passed, {counts.get('failed', 0)} failed, {skipped} skipped"
             + (" (a skip usually means pyarrow is not installed)" if skipped else ""), r["seconds"], counts)


def check_unseen(c: Check, quick: bool) -> None:
    r = c.run("unseen formats", [PY, "scripts/evaluate_unseen_formats.py", "--json", "--learned"], "unseen_formats.json", 900)
    try:
        d = _json_tail(r["stdout"])
    except ValueError:
        c.record("Formats with no parser", "claim", "FAIL", f"script failed (exit {r['code']})", r["seconds"], {})
        return
    g = {k: sum(len(row[k]) for row in d["generic"]) for k in ("correct", "missed", "wrong")}
    learned = d.get("learned") or []
    lc = sum(x["learned"]["correct"] for x in learned)
    lt = sum(x["learned"]["correct"] + x["learned"]["missed"] + x["learned"]["wrong"] for x in learned)
    lw = sum(x["learned"]["wrong"] for x in learned)
    ok = g["wrong"] == 0 and lw == 0
    c.record("Formats with no parser", "claim", "PASS" if ok else "FAIL",
             f"{g['correct']} correct, {g['missed']} missed, {g['wrong']} wrong over {len(d['generic'])} formats; "
             f"learned parsers {lc}/{lt} fields, {lw} wrong", r["seconds"],
             {**g, "formats": len(d["generic"]), "learned_correct": lc, "learned_total": lt, "learned_wrong": lw})


def check_trace(c: Check, quick: bool) -> None:
    r = c.run("trace one line", [PY, "scripts/trace_line.py"], "trace_line.log", 300)
    m = re.search(r"\b([0-9a-f]{64})\b", r["stdout"])
    c.record("One line traced end to end", "claim", "PASS" if r["code"] == 0 else "FAIL",
             "every stage printed" + (f"; raw SHA-256 {m.group(1)[:16]}..." if m else ""), r["seconds"],
             {"raw_sha256": m.group(1) if m else None})


def _median(xs: List[float]) -> float:
    return round(statistics.median(xs), 1) if xs else 0.0


def check_benchmark(c: Check, quick: bool, repeat: int, workers: List[int]) -> None:
    n = 20_000 if quick else 100_000
    runs = []
    total_s = 0.0
    for i in range(repeat):
        r = c.run(f"benchmark, one process, run {i + 1}/{repeat}",
                  [PY, "scripts/benchmark.py", "-n", str(n), "-b", "1000", "--read", "--json"],
                  f"benchmark_single_{i + 1}.json", 3600)
        total_s += r["seconds"]
        try:
            runs.append(_json_tail(r["stdout"]))
        except ValueError:
            pass
    if not runs:
        c.record("Throughput, one process", "measurement", "FAIL", "benchmark failed", total_s, {})
        return
    eps = [x["ingest"]["events_per_second"] for x in runs]
    single = {
        "events": n, "runs": len(runs), "events_per_second_median": _median(eps), "events_per_second_min": min(eps),
        "events_per_second_max": max(eps), "per_day_millions_median": round(_median(eps) * 86_400 / 1e6, 1),
        "batch_ms_p50_median": _median([x["ingest"]["batch_ms_p50"] for x in runs]),
        "batch_ms_p99_median": _median([x["ingest"]["batch_ms_p99"] for x in runs]),
        "parse_us_per_line_median": _median([x["ingest"]["parse_only_us_per_line"] for x in runs]),
        "read_ms_median": {k: _median([x["read"][k] for x in runs if "read" in x]) for k in runs[0].get("read", {})},
    }
    c.record("Throughput, one process", "measurement", "MEASURED",
             f"{single['events_per_second_median']:,.0f} events/s median of {len(runs)} runs "
             f"({min(eps):,}-{max(eps):,}), {single['per_day_millions_median']}M/day; batch p50 "
             f"{single['batch_ms_p50_median']} ms, p99 {single['batch_ms_p99_median']} ms", total_s, single)

    r = c.run("benchmark without the full-text index",
              [PY, "scripts/benchmark.py", "-n", str(n), "-b", "1000", "--json"], "benchmark_no_index.json", 3600,
              env={"SEARCH_INDEX": "false"})
    try:
        x = _json_tail(r["stdout"])["ingest"]
        c.record("Throughput, forwarder mode (no search index)", "measurement", "MEASURED",
                 f"{x['events_per_second']:,} events/s, {x['per_day_millions']}M/day", r["seconds"], x)
    except (ValueError, KeyError):
        c.record("Throughput, forwarder mode (no search index)", "measurement", "FAIL", "benchmark failed",
                 r["seconds"], {})

    per_worker = 10_000 if quick else 50_000
    scaling = []
    for w in workers:
        r = c.run(f"benchmark, {w} shards", [PY, "scripts/benchmark.py", "-n", str(per_worker), "-b", "1000",
                                              "-w", str(w), "--json"], f"benchmark_{w}_shards.json", 3600)
        try:
            x = _json_tail(r["stdout"])
        except ValueError:
            continue
        rate = x["events_per_second"]
        scaling.append({"shards": w, "events_per_second": rate, "per_day_millions": x["per_day_millions"],
                        "per_shard_average": round(rate / w), "seconds": r["seconds"]})
    if scaling:
        best = max(scaling, key=lambda s: s["events_per_second"])
        base = single["events_per_second_median"]
        for s in scaling:
            s["speedup_vs_one_process"] = round(s["events_per_second"] / base, 2) if base else None
        reach = best["events_per_second"] >= BILLION_PER_DAY
        c.record("Throughput, sharded", "measurement", "MEASURED",
                 f"best {best['events_per_second']:,} events/s with {best['shards']} shards "
                 f"({best['per_day_millions']}M/day); 1 billion/day needs {BILLION_PER_DAY:,.0f}/s: "
                 f"{'reached' if reach else 'not reached on this machine'}",
                 sum(s["seconds"] for s in scaling), {"runs": scaling, "reaches_one_billion_per_day": reach})


def check_public(c: Check, quick: bool, fetch: bool) -> None:
    cmd = [PY, "scripts/evaluate_public_samples.py", "--json", "--markdown", str(c.out / "PUBLIC_SAMPLES.md")]
    if not fetch:
        cmd.append("--no-fetch")
    r = c.run("real third-party logs", cmd, "public_samples.json", 3600)
    try:
        d = _json_tail(r["stdout"])
    except ValueError:
        c.record("Real third-party logs", "claim", "FAIL",
                 f"script failed (exit {r['code']}); see public_samples.json" +
                 ("; it needs git and internet the first time" if fetch else ""), r["seconds"], {})
        return
    from scripts.evaluate_public_samples import by_cause, totals
    e, l = totals(d["per_source"]), totals(d["per_source"], loghub=True)
    e2e = d["end_to_end"]
    causes = by_cause(d["disagreements"])
    data = {"lines": e["lines"] + l["lines"], "sources": len(d["per_source"]),
            "crashes": e["crashed"] + l["crashed"], "ocsf_invalid": e["ocsf_invalid"] + l["ocsf_invalid"],
            "agree": e["agree"], "disagree": e["wrong"], "left_empty": e["missed"],
            "unexplained": causes.get("other", 0), "archived": e2e["archived"], "submitted": e2e["submitted"],
            "chain_valid": e2e["chain_valid"], "end_to_end_events_per_second": e2e["events_per_second"]}
    ok = (data["crashes"] == 0 and data["ocsf_invalid"] == 0 and data["chain_valid"]
          and data["archived"] == data["submitted"])
    c.record("Real third-party logs", "claim", "PASS" if ok else "FAIL",
             f"{data['lines']:,} lines from {data['sources']} sources: {data['crashes']} crashes, "
             f"{data['ocsf_invalid']} invalid OCSF, {data['archived']:,}/{data['submitted']:,} archived and chained, "
             f"chain {'verified' if data['chain_valid'] else 'BROKEN'}; against Elastic: {data['agree']:,} agree, "
             f"{data['disagree']:,} disagree ({data['unexplained']} unexplained), {data['left_empty']:,} left empty",
             r["seconds"], data)


def check_baseline(c: Check, quick: bool) -> None:
    seeds = "1" if quick else "1,2,3"
    r = c.run("baseline detector on synthetic days", [PY, "scripts/evaluate_baseline.py", "--seeds", seeds, "--json",
                                                        "--report", str(c.out / "ML_EVALUATION.md")],
              "ml_evaluation.log", 3600)
    try:
        d = _json_tail(r["stdout"])
    except ValueError:
        c.record("Baseline detector, synthetic days", "claim", "FAIL", f"script failed (exit {r['code']})",
                 r["seconds"], {})
        return
    expected_miss = {a.name for a in _attacks() if a.expected_miss}     # built to stay under the minimums
    caught = [sum(1 for k, v in s["detected"].items() if v and k not in expected_miss) for s in d]
    detectable = [sum(1 for k in s["detected"] if k not in expected_miss) for s in d]
    missed_as_designed = all(not s["detected"][k] for s in d for k in s["detected"] if k in expected_miss)
    ff = [s["false_flags"] for s in d]
    ok = (all(s["chain_valid"] and s["findings_invalid"] == 0 and s["rerun_written"] == 0
              and s["evidence_ok"] == s["evidence_total"] for s in d) and caught == detectable)
    c.record("Baseline detector, synthetic days", "claim", "PASS" if ok else "FAIL",
             f"{len(d)} seed{'s' if len(d) != 1 else ''}: detectable attacks caught {', '.join(f'{a}/{b}' for a, b in zip(caught, detectable))}; "
             f"designed misses {'missed' if missed_as_designed else 'CAUGHT'}; false flags {', '.join(map(str, ff))}; "
             f"findings valid, chain verified, rerun wrote nothing: {'yes' if ok else 'NO'}", r["seconds"],
             {"seeds": d, "caught": caught, "detectable": detectable, "false_flags": ff})


def _attacks():
    from scripts.synthetic_network import generate
    return generate(1, hours=24, hosts=4).attacks


def check_container(c: Check, quick: bool) -> None:
    if not shutil.which("docker") or not _run_text(["docker", "version", "--format", "{{.Server.Version}}"]):
        c.record("Container image", "claim", "SKIPPED", "Docker is not installed or not running", 0, {})
        return
    r = c.run("container image build and checks", ["sh", "scripts/check_image.sh", "tracelog:check"],
              "container.log", 3600)
    oks = [l for l in r["stdout"].splitlines() if l.startswith("ok")]
    fails = [l for l in r["stdout"].splitlines() if "FAIL" in l]
    size = re.search(r"^(\d+) MB$", r["stdout"], re.M)
    ok = r["code"] == 0 and not fails
    c.record("Container image", "claim", "PASS" if ok else "FAIL",
             f"{len(oks)} checks ok, {len(fails)} failed" + (f"; image {size.group(1)} MB" if size else "")
             + ("" if ok else f"; see container.log (exit {r['code']})"), r["seconds"],
             {"ok": oks, "failed": fails, "image_mb": int(size.group(1)) if size else None})


# ---------------------------------------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------------------------------------
def summary_md(info: Dict[str, Any], results: List[Dict[str, Any]], started: str, seconds: float) -> str:
    lines = [f"# TRACELOG checks on {info['hostname']}", "",
             f"Run {started}, {seconds / 60:.1f} minutes, commit `{info['git_commit']}`"
             + (f" with {info['git_uncommitted_files']} uncommitted files" if info["git_uncommitted_files"] else "")
             + ".", "", "## The machine", "", "| | |", "|---|---|"]
    rows = [("CPU", info.get("cpu")), ("Physical cores / logical CPUs", f"{info.get('physical_cores')} / {info.get('logical_cpus')}"),
            ("Memory", f"{info.get('memory_gb')} GB"), ("OS", info.get("os")), ("Under WSL", "yes" if info["wsl"] else "no"),
            ("Python / SQLite", f"{info['python']} / {info['sqlite']}"),
            ("On mains power", {True: "yes", False: "NO: on battery", None: "unknown"}[info.get("on_mains_power")]),
            ("CPU governor", info.get("cpu_governor") or "unknown"), ("Docker", info.get("docker") or "not available"),
            ("Packages", ", ".join(f"{k} {v}" for k, v in info["packages"].items() if v))]
    lines += [f"| {k} | {v} |" for k, v in rows]
    if info["repo_on_windows_drive"]:
        lines += ["", "**Warning:** the code is on a Windows drive (`/mnt/...`). Disk access there is much slower "
                      "from WSL, so the throughput numbers understate this machine. Clone into the Linux home "
                      "directory and run again."]
    lines += ["", "## Results", "", "| Check | Status | What it measured | Seconds |", "|---|---|---|---|"]
    lines += [f"| {r['name']} | {r['status']} | {r['result']} | {r['seconds']} |" for r in results]
    bench = next((r for r in results if r["name"] == "Throughput, one process" and r["data"]), None)
    if bench and bench["data"].get("read_ms_median"):
        lines += ["", "## Read-side timings (median, ms)", "", "| What a person waits for | ms |", "|---|---|"]
        labels = {"events_page_ms": "Explorer page", "events_search_ms": "search over the archive",
                  "events_by_ip_ms": "filter by address", "dashboard_ms": "dashboard figures",
                  "export_ocsf_ms": "OCSF export", "verify_chain_ms": "full chain verification"}
        lines += [f"| {labels.get(k, k)} | {v} |" for k, v in bench["data"]["read_ms_median"].items()]
    shard = next((r for r in results if r["name"] == "Throughput, sharded" and r["data"]), None)
    if shard:
        lines += ["", "## Scaling with shards", "", "| Shards | Events/s | Per shard | vs one process | Million/day |",
                  "|---|---|---|---|---|"]
        lines += [f"| {s['shards']} | {s['events_per_second']:,} | {s['per_shard_average']:,} | "
                  f"{s['speedup_vs_one_process']}x | {s['per_day_millions']} |" for s in shard["data"]["runs"]]
    failed = [r["name"] for r in results if r["status"] == "FAIL"]
    lines += ["", "## Verdict", "", ("Every claim held on this machine." if not failed else
                                     "These did not hold and need a look before any number is quoted: " +
                                     ", ".join(failed) + ".")]
    lines += ["", "Quote a throughput figure only with the CPU line above beside it.", ""]
    return "\n".join(lines)


def compare(a: Path, b: Path) -> str:
    A, B = (json.loads((p / "summary.json").read_text()) for p in (a, b))

    def get(s, name, *path):
        r = next((x for x in s["results"] if x["name"] == name), None)
        v = r["data"] if r else None
        for k in path:
            v = v.get(k) if isinstance(v, dict) else None
        return v

    rows = [("Throughput, one process (events/s, median)", "Throughput, one process", ("events_per_second_median",)),
            ("Batch latency p50 (ms)", "Throughput, one process", ("batch_ms_p50_median",)),
            ("Batch latency p99 (ms)", "Throughput, one process", ("batch_ms_p99_median",)),
            ("Parsing alone (us/line)", "Throughput, one process", ("parse_us_per_line_median",)),
            ("Forwarder mode (events/s)", "Throughput, forwarder mode (no search index)", ("events_per_second",)),
            ("Dashboard figures (ms)", "Throughput, one process", ("read_ms_median", "dashboard_ms")),
            ("Full chain verification (ms)", "Throughput, one process", ("read_ms_median", "verify_chain_ms")),
            ("Real logs end to end (events/s)", "Real third-party logs", ("end_to_end_events_per_second",))]
    out = [f"Ratio is the second run divided by the first: above 1 is faster for events/s, below 1 is faster "
           f"for milliseconds.", "",
           f"| | {a.name} | {b.name} | Ratio |", "|---|---|---|---|",
           f"| CPU | {A['machine'].get('cpu')} | {B['machine'].get('cpu')} | |",
           f"| Cores / CPUs | {A['machine'].get('physical_cores')} / {A['machine'].get('logical_cpus')} | "
           f"{B['machine'].get('physical_cores')} / {B['machine'].get('logical_cpus')} | |"]
    for label, name, path in rows:
        x, y = get(A, name, *path), get(B, name, *path)
        ratio = f"{y / x:.2f}x" if isinstance(x, (int, float)) and isinstance(y, (int, float)) and x else ""
        out.append(f"| {label} | {x if x is not None else '-'} | {y if y is not None else '-'} | {ratio} |")
    sa = {s["shards"]: s["events_per_second"] for s in (get(A, "Throughput, sharded", "runs") or [])}
    sb = {s["shards"]: s["events_per_second"] for s in (get(B, "Throughput, sharded", "runs") or [])}
    for w in sorted(set(sa) | set(sb)):
        x, y = sa.get(w), sb.get(w)
        out.append(f"| {w} shards (events/s) | {x or '-'} | {y or '-'} | {f'{y / x:.2f}x' if x and y else ''} |")
    for r in B["results"]:
        if r["kind"] == "claim":
            ra = next((x for x in A["results"] if x["name"] == r["name"]), {"status": "-"})
            out.append(f"| {r['name']} | {ra['status']} | {r['status']} | |")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="smaller runs; skips the public samples and the image build")
    ap.add_argument("--skip", default="", help="comma list of: tests, unseen, trace, benchmark, public, baseline, container")
    ap.add_argument("--repeat", type=int, default=3, help="one-process benchmark runs to take the median of (default 3)")
    ap.add_argument("--workers", default="", help="shard counts to benchmark, e.g. 2,4,8 (default: 2, 4, ... up to the "
                                                  "number of logical CPUs)")
    ap.add_argument("--no-fetch", action="store_true", help="use public samples already in data/public_samples")
    ap.add_argument("--out", type=Path, help="results folder (default results/<host>-<time>)")
    ap.add_argument("--compare", nargs=2, type=Path, metavar=("OLD", "NEW"), help="compare two results folders")
    args = ap.parse_args(argv)

    if args.compare:
        text = compare(*args.compare)
        print(text)
        (args.compare[1] / f"compare-with-{args.compare[0].name}.md").write_text(text, encoding="utf-8")
        return 0

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    if args.quick:
        skip |= {"public", "container"}
        args.repeat = min(args.repeat, 1)
    cpus = os.cpu_count() or 2
    workers = [int(w) for w in args.workers.split(",") if w.strip()] if args.workers else \
        sorted({w for w in (2, 4, 8, 16, 32) if w <= cpus} | {cpus})
    if args.quick:
        workers = workers[:2]
    started = datetime.now().strftime("%Y-%m-%d %H:%M")
    out = args.out or ROOT / "results" / f"{socket.gethostname()}-{datetime.now():%Y%m%d-%H%M}"
    out.mkdir(parents=True, exist_ok=True)
    info = machine()
    (out / "machine.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"TRACELOG checks on {info['hostname']}: {info.get('cpu')}, {info.get('logical_cpus')} CPUs, "
          f"{info.get('memory_gb')} GB, Python {info['python']}\nresults -> {out}\n", flush=True)
    if info["repo_on_windows_drive"]:
        print("WARNING: the code is on a Windows drive (/mnt/...); throughput will be understated.\n", flush=True)
    if info.get("on_mains_power") is False:
        print("WARNING: running on battery; plug in for throughput numbers worth quoting.\n", flush=True)

    c = Check(out)
    t0 = time.perf_counter()
    steps: List[tuple] = [
        ("tests", lambda: check_tests(c, args.quick)),
        ("unseen", lambda: check_unseen(c, args.quick)),
        ("trace", lambda: check_trace(c, args.quick)),
        ("benchmark", lambda: check_benchmark(c, args.quick, max(1, args.repeat), workers)),
        ("public", lambda: check_public(c, args.quick, fetch=not args.no_fetch)),
        ("baseline", lambda: check_baseline(c, args.quick)),
        ("container", lambda: check_container(c, args.quick)),
    ]
    for key, fn in steps:
        if key in skip:
            continue
        print(f"[{key}]", flush=True)
        try:
            fn()
        except Exception as exc:        # one broken check must not lose the others' results
            c.record(key, "claim", "FAIL", f"the runner itself failed: {exc!r}", 0, {})
    seconds = time.perf_counter() - t0
    summary = {"machine": info, "started": started, "seconds": round(seconds, 1), "results": c.results}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (out / "summary.md").write_text(summary_md(info, c.results, started, seconds), encoding="utf-8")
    failed = [r for r in c.results if r["status"] == "FAIL"]
    print(f"\n{len(c.results)} checks in {seconds / 60:.1f} min, {len(failed)} failed. Summary: {out / 'summary.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
