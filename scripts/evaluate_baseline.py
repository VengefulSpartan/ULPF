#!/usr/bin/env python3
"""
Evaluate the baseline detector on synthetic days with attacks injected at known times
(scripts/synthetic_network.py), end to end through the real pipeline:

  generate FortiGate syslog lines -> StreamIngestor (archive, parse, OCSF, hash chain) -> features from
  the stored events -> baseline -> flags written back as Detection Findings through the same writer

and then check what was written: every finding valid OCSF, the chain intact, every evidence event
present with the hash of its raw line, a second run writing nothing, and the hour-by-hour live path
giving the same flags as one pass over the day.

    python scripts/evaluate_baseline.py                       # seeds 1-3, report to docs/ML_EVALUATION.md
    python scripts/evaluate_baseline.py --seeds 1 --no-report

These are synthetic days: they show what the detector catches and misses on a network whose
behaviour is known, not how it will do on a real one. Its false-flag rate on real traffic is unknown
until it is run on real traffic.
"""
import argparse
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WARMUP_HOURS = 2          # windows before this are not scored: nothing has history yet
LIVE_CHECK_HOURS = (13, 20)   # hours replayed one at a time, as the scheduler runs, on the first seed


def _overlaps(flag, attack) -> bool:
    return flag.window_start_ms <= attack.end_ms and flag.window_end_ms > attack.start_ms


def match(flags, attacks) -> Dict[str, Any]:
    by_attack = {a.name: [] for a in attacks}
    false_flags = []
    for fl in flags:
        hit = [a for a in attacks if (fl.entity_type, fl.entity) in a.entities and _overlaps(fl, a)]
        for a in hit:
            by_attack[a.name].append(fl)
        if not hit:
            false_flags.append(fl)
    return {"by_attack": by_attack, "false_flags": false_flags}


def run_seed(seed: int, hours: int, hosts: int, live_check: bool) -> Dict[str, Any]:
    from scripts.benchmark import setup_database
    from scripts.synthetic_network import generate

    tmp = Path(tempfile.mkdtemp(prefix=f"tracelog-baseline-{seed}-"))
    database = setup_database(tmp / "eval.db")
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor
    from backend.services.integrity.ledger import IntegrityLedger
    from backend.services.ml import baseline, features as feat
    from backend.services.normalization.ocsf_export import to_ocsf, validate
    from backend.services import jsonio

    sc = generate(seed, hours=hours, hosts=hosts)
    t0 = time.perf_counter()
    ingestor = StreamIngestor()
    for i in range(0, len(sc.lines), 1000):
        ingestor.ingest([InboundRecord(raw=line.encode("utf-8"), transport="syslog-udp", input_name="syslog",
                                       peer_ip="10.10.0.1") for _, line in sc.lines[i:i + 1000]])
    ingest_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    events = feat.events_from_db(database)
    load_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    scored_from = sc.start_ms + WARMUP_HOURS * 3600 * 1000
    result = baseline.detect(events, since_ms=scored_from)
    detect_s = time.perf_counter() - t0
    stored = baseline.write_findings(result.flags, database)
    matched = match(result.flags, sc.attacks)

    # what was written, checked
    with database.get_connection() as conn:
        findings = conn.execute("SELECT normalized_json FROM normalized_events WHERE parser_pack = ?",
                                (feat.DETECTOR_PARSER,)).fetchall()
        invalid = sum(1 for r in findings if validate(to_ocsf(jsonio.loads(r["normalized_json"]))))
        evidence_ok = evidence_total = 0
        for fl in result.flags:
            for uid in fl.event_uids:
                evidence_total += 1
                row = conn.execute("SELECT r.raw_text, r.raw_hash FROM normalized_events n JOIN raw_logs r "
                                   "ON r.id = n.raw_id WHERE n.id = ?", (uid,)).fetchone()
                if row and hashlib.sha256(row["raw_text"].encode("utf-8")).hexdigest() == row["raw_hash"]:
                    evidence_ok += 1
    chain = IntegrityLedger.verify_chain()
    rerun_written = len(baseline.write_findings(result.flags, database))

    live_same = None
    if live_check:
        lo, hi = LIVE_CHECK_HOURS
        live = set()
        for h in range(lo, hi):
            out = baseline.run(database, until_ms=sc.start_ms + (h + 1) * 3600 * 1000, score_hours=1, write=False)
            live |= {f["finding_uid"] for f in out["findings"]}
        batch = {fl.finding_uid for fl in result.flags
                 if sc.start_ms + lo * 3600 * 1000 <= fl.window_start_ms < sc.start_ms + hi * 3600 * 1000}
        live_same = {"hours": f"{lo:02d}:00-{hi:02d}:00", "live": len(live), "batch": len(batch),
                     "identical": live == batch}

    return {
        "seed": seed, "lines": len(sc.lines), "events": int(len(events)), "attacks": sc.attacks,
        "benign_notes": sc.benign_notes, "flags": result.flags, "matched": matched,
        "windows_scored": result.windows_scored, "windows_without_history": result.windows_without_history,
        "findings_written": len(stored), "findings_invalid": invalid, "chain_valid": chain.is_valid,
        "chain_records": chain.total_records, "evidence_ok": evidence_ok, "evidence_total": evidence_total,
        "rerun_written": rerun_written, "live_check": live_same,
        "seconds": {"ingest": round(ingest_s, 1), "load": round(load_s, 1), "detect": round(detect_s, 1)},
        "start_ms": sc.start_ms,
    }


def _mins(ms: float) -> str:
    return f"{ms / 60000:.1f} min"


def _why(fl, notes) -> str:
    for kind, entity, start, end, why in notes:
        if (fl.entity_type, fl.entity) == (kind, entity) and fl.window_start_ms <= end and fl.window_end_ms > start:
            return why
    return "no injected cause"


def report(results: List[Dict[str, Any]], hours: int, hosts: int) -> str:
    from backend.services.ml import baseline

    seeds = [r["seed"] for r in results]
    attacks = results[0]["attacks"]
    lines = [
        "# Baseline detector on synthetic days",
        "",
        "Generated by `python scripts/evaluate_baseline.py`; rerun it to reproduce every number here.",
        "",
        f"**These are synthetic days**: {hours} h of FortiGate logs from {hosts} internal hosts, internet scan "
        f"noise and 25 VPN users, with eight attacks injected at known times (scripts/synthetic_network.py). "
        "They show what the detector catches and misses when the network's behaviour is known. They do not "
        "show its false-flag rate on a real network, which is unknown until it runs on one: the benign "
        "traffic here comes from steady random processes, and real traffic is burstier.",
        "",
        f"Seeds {', '.join(map(str, seeds))}. Every line went through the real pipeline (archive, FortiGate pack, "
        "OCSF, hash chain); the features were computed from the stored events; each flag was written back "
        "through the same writer as a Detection Finding. Windows in the first "
        f"{WARMUP_HOURS} h are not scored. Settings: threshold {baseline.THRESHOLD}, own history >= "
        f"{baseline.MIN_OWN_HISTORY} windows, peers >= {baseline.MIN_PEER_HISTORY}, lookback "
        f"{baseline.LOOKBACK_HOURS} h, minimum increases as in `baseline.MIN_EXCESS`, all fixed before the first run.",
        "",
        "## Attacks",
        "",
        "| Attack | What was injected | Detected | Time to detection* | What the flag said (seed " f"{seeds[0]}) |",
        "|---|---|---|---|---|",
    ]
    for a in attacks:
        hits = [r["matched"]["by_attack"][a.name] for r in results]
        detected = sum(1 for h in hits if h)
        delays = [min(fl.window_end_ms for fl in h) - a_r.start_ms
                  for h, a_r in zip(hits, [next(x for x in r["attacks"] if x.name == a.name) for r in results]) if h]
        delay = (f"{_mins(statistics.median(delays))}" + (f" ({_mins(min(delays))}-{_mins(max(delays))})"
                                                          if len(delays) > 1 and min(delays) != max(delays) else "")
                 if delays else "—")
        first = hits[0][0] if hits[0] else None
        said = f"{first.title()}: {first.summary(5)}" if first else "no flag"
        verdict = f"{detected}/{len(results)}" + (" (expected miss)" if a.expected_miss else "")
        lines.append(f"| {a.name} | {a.note} | {verdict} | {delay} | {said} |")
    lines += [
        "",
        "\\* From the attack's first line to the end of the first flagged window: when the window closes, "
        "the flag can be computed. Run live (`BASELINE_EVERY_MINUTES=5`), add up to 30 s of grace and the "
        "run itself.",
        "",
        "The two expected misses stay under the smallest increase the detector flags in every 5-minute "
        "window (15 ports, 50 MB), which is the point of including them: a per-window baseline does not "
        "see an attack spread thin over hours. Catching them needs longer windows or a detector that "
        "accumulates over time.",
        "",
        "## False flags",
        "",
        "Flags that match no injected attack (entity and time).",
        "",
        "| Seed | Entity-windows scored | Not scored (no history yet) | False flags | Per 1,000 scored | Which |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        ff = r["matched"]["false_flags"]
        which = "; ".join(f"{fl.title()} at {baseline._iso(fl.window_start_ms)[11:16]} ({_why(fl, r['benign_notes'])})"
                          for fl in ff) or "—"
        rate = 1000 * len(ff) / r["windows_scored"] if r["windows_scored"] else 0
        lines.append(f"| {r['seed']} | {r['windows_scored']:,} | {r['windows_without_history']:,} | {len(ff)} | "
                     f"{rate:.2f} | {which} |")
    lines += [
        "",
        "The nightly backup is benign and is flagged: with 24 hours of history, a once-a-day 300 MB upload "
        "has never been seen before. A person marks it expected; a longer lookback or a per-hour-of-day "
        "baseline would learn it.",
        "",
        "## What was written, checked",
        "",
        "| Seed | Lines | Findings written | Invalid OCSF | Chain | Evidence events found, raw hash matching | "
        "Second run wrote | Seconds: ingest / read events / features and scores |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        s = r["seconds"]
        lines.append(f"| {r['seed']} | {r['lines']:,} | {r['findings_written']} | {r['findings_invalid']} | "
                     f"{'verified' if r['chain_valid'] else 'BROKEN'}, {r['chain_records']:,} records | "
                     f"{r['evidence_ok']}/{r['evidence_total']} | {r['rerun_written']} | "
                     f"{s['ingest']} / {s['load']} / {s['detect']} |")
    live = results[0]["live_check"]
    if live:
        lines += ["", f"Live path, seed {seeds[0]}: replaying {live['hours']} one hour at a time as the scheduler "
                      f"does gave {live['live']} flags, one pass over the day gave {live['batch']} for the same "
                      f"hours: {'identical' if live['identical'] else 'DIFFERENT'}. A window is scored from its "
                      "own events and earlier ones only, so when it is scored does not change the answer."]
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", default="1,2,3")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--hosts", type=int, default=30)
    ap.add_argument("--report", type=Path, default=ROOT / "docs" / "ML_EVALUATION.md")
    ap.add_argument("--no-report", action="store_true")
    ap.add_argument("--json", action="store_true", help="print a JSON summary")
    args = ap.parse_args(argv)

    results = []
    for n, seed in enumerate(int(s) for s in args.seeds.split(",")):
        r = run_seed(seed, args.hours, args.hosts, live_check=(n == 0))
        found = sum(1 for a in r["attacks"] if r["matched"]["by_attack"][a.name])
        print(f"seed {seed}: {r['lines']:,} lines, {len(r['flags'])} flags, attacks detected {found}/"
              f"{len(r['attacks'])}, false flags {len(r['matched']['false_flags'])}, chain "
              f"{'verified' if r['chain_valid'] else 'BROKEN'}, {r['seconds']}", flush=True)
        results.append(r)
    text = report(results, args.hours, args.hosts)
    if not args.no_report:
        args.report.write_text(text, encoding="utf-8")
        print(f"report: {args.report}")
    if args.json:
        print(json.dumps([{k: v for k, v in r.items() if k in (
            "seed", "lines", "windows_scored", "findings_written", "findings_invalid", "chain_valid",
            "evidence_ok", "evidence_total", "rerun_written", "live_check")} |
            {"detected": {a.name: bool(r["matched"]["by_attack"][a.name]) for a in r["attacks"]},
             "false_flags": len(r["matched"]["false_flags"])} for r in results], indent=2))
    ok = all(r["chain_valid"] and not r["findings_invalid"] and not r["rerun_written"]
             and r["evidence_ok"] == r["evidence_total"] for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
