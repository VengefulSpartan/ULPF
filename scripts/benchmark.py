"""
Measure TRACELOG's throughput end to end, on a throwaway database.

    python scripts/benchmark.py                      # 20k events, batches of 500
    python scripts/benchmark.py -n 200000 -b 1000    # bigger run
    python scripts/benchmark.py --read               # also time search, dashboard and export
    python scripts/benchmark.py -w 4                 # 4 shards in parallel, one chain each
    python scripts/benchmark.py --json               # machine-readable

The corpus mixes what a perimeter really sends: lines vendor packs know (Cisco ASA,
Palo Alto, FortiGate, Suricata), lines only the generic parser can read (formats with
no pack), and junk. Values vary line by line, so no cache can flatter the result.

Reported: events/s for the whole path (decode, parse, normalise to OCSF, archive,
hash-chain, store), per-batch latency, and the same rate expressed per day, which is
the number to quote. Nothing here is a constant.
"""
import argparse
import json
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SERVICES = [443, 80, 22, 53, 3389, 445, 8443]
ACTIONS = ["allow", "deny"]


def _ip(r, internal=True):
    return f"10.{r.randint(0, 3)}.{r.randint(0, 255)}.{r.randint(2, 254)}" if internal else \
        f"{r.choice([203, 198, 93, 185])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def build_corpus(n: int, seed: int = 7):
    """n lines: 80 % vendor packs, 15 % formats with no pack, 5 % lines nothing parses."""
    r = random.Random(seed)
    lines = []
    for i in range(n):
        src, dst = _ip(r), _ip(r, False)
        sport, dport = r.randint(1025, 65000), r.choice(SERVICES)
        act = r.choice(ACTIONS)
        ts = f"Sep {r.randint(10, 28)} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}"
        pick = r.random()
        if pick < 0.30:      # Cisco ASA
            lines.append(f"<166>{ts} ciscoasa %ASA-6-302013: Built inbound TCP connection {r.randint(10**4, 10**6)} "
                         f"for outside:{dst}/{sport} to inside:{src}/{dport}")
        elif pick < 0.55:    # FortiGate key=value
            lines.append(f'<189>date=2026-09-21 time=10:20:00 devname="FGT-HQ" devid="FG100FTK19000001" '
                         f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                         f'srcip={src} srcport={sport} srcintf="port2" dstip={dst} dstport={dport} dstintf="wan1" '
                         f'proto=6 action="{act}" policyid=12 service="HTTPS" sentbyte={r.randint(0, 9000)} '
                         f'rcvdbyte={r.randint(0, 9000)}')
        elif pick < 0.70:    # Palo Alto CEF
            lines.append(f"CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src={src} dst={dst} spt={sport} "
                         f"dpt={dport} proto=TCP act={act} cs1Label=Rule cs1=allow-web")
        elif pick < 0.80:    # Suricata EVE
            lines.append(json.dumps({"timestamp": "2026-09-21T10:15:02.123456+0000", "event_type": "alert",
                                     "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport,
                                     "proto": "TCP", "alert": {"signature": "ET SCAN Possible Nmap",
                                                               "severity": r.randint(1, 3)}}))
        elif pick < 0.95:    # no pack: WatchGuard-style positional, Huawei-style, and a bare app line
            style = r.random()
            if style < 0.4:
                lines.append(f'<142>{ts} WatchGuard-XTM FVE123 firewall: msg_id="3000-0148" '
                             f'{"Allow" if act == "allow" else "Deny"} 1-Trusted 0-External {r.randint(40, 1500)} '
                             f'tcp 20 {r.randint(32, 128)} {src} {dst} {sport} {dport} offset 10 S')
            elif style < 0.75:
                lines.append(f"<188>{ts} 2026 USG6000 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=6, "
                             f"source-ip={src}, source-port={sport}, destination-ip={dst}, "
                             f"destination-port={dport}, source-zone=trust, rule-name=allow.")
            else:
                lines.append(f"{ts} edge-proxy[{r.randint(100, 9999)}]: request user={r.choice(['alice', 'bob'])} "
                             f"from {src} to {dst}:{dport} status={r.choice([200, 403, 502])} ms={r.randint(1, 900)}")
        else:                # nothing parses this
            lines.append(f"{ts} kernel: [{r.random() * 10**5:.6f}] unexpected diagnostic blob {r.randint(1, 10**9)}")
    return lines


def run_shard(args):
    """One shard in its own process: its own database, its own chain, its own share of the lines."""
    index, events, batch, directory = args
    setup_database(Path(directory) / f"shard-{index}.db")
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor

    ingestor = StreamIngestor()
    lines = build_corpus(events, seed=7 + index)
    started = time.perf_counter()
    stored = 0
    for i in range(0, len(lines), batch):
        stored += len(ingestor.ingest([InboundRecord(raw=l.encode(), transport="syslog-udp", input_name=f"s{index}",
                                                     peer_ip=f"192.0.2.{index + 1}")
                                       for l in lines[i:i + batch]]))
    return {"shard": index, "events": stored, "seconds": round(time.perf_counter() - started, 3)}


def run_sharded(workers: int, events: int, batch: int) -> Dict[str, Any]:
    """
    Several ingest workers at once, each owning its own database and hash chain.

    This is the sharded deployment measured honestly: nothing is shared between workers, so the
    aggregate is what a machine of this size does, and each shard's chain verifies on its own.
    """
    import multiprocessing as mp

    with tempfile.TemporaryDirectory() as directory:
        jobs = [(i, events, batch, directory) for i in range(workers)]
        started = time.perf_counter()
        with mp.get_context("spawn").Pool(workers) as pool:
            results = pool.map(run_shard, jobs)
        wall = time.perf_counter() - started
    total = sum(r["events"] for r in results)
    # the shards ingest at the same time, so the rate is everything they stored divided by the
    # longest shard, not by the wall clock, which also holds process start-up and corpus building
    slowest = max(r["seconds"] for r in results)
    return {"workers": workers, "events": total, "ingest_seconds": slowest, "wall_seconds": round(wall, 3),
            "events_per_second": round(total / slowest), "per_day_millions": round(total / slowest * 86400 / 1e6, 1),
            "per_shard": results}


def setup_database(path: Path):
    """Point every module that holds a database handle at a fresh file, the way the tests do."""
    import backend.services.integrity.ledger as ledger_module
    import backend.services.storage.db as db_module
    from backend.services.storage.db import Database

    database = Database(db_path=path)
    db_module.db = database
    ledger_module.db = database
    for mod in ("backend.api.events", "backend.api.analytics", "backend.api.export", "backend.api.integrity",
                "backend.api.ingestion", "backend.api.sources", "backend.services.ingestion.pipeline"):
        m = __import__(mod, fromlist=["db"])
        if hasattr(m, "db"):
            setattr(m, "db", database)
    return database


def run_ingest(lines, batch_size: int):
    from backend.services.ingestion.stream import InboundRecord, StreamIngestor
    from backend.services.parsing.dispatch import parse_log

    ingestor = StreamIngestor()
    # parse-only, on a copy of the same lines, to show how the time splits
    sample = lines[: min(2000, len(lines))]
    t0 = time.perf_counter()
    for line in sample:
        parse_log(line)
    parse_only = (time.perf_counter() - t0) / len(sample)

    latencies, stored, t_start = [], 0, time.perf_counter()
    for i in range(0, len(lines), batch_size):
        chunk = lines[i:i + batch_size]
        records = [InboundRecord(raw=l.encode(), transport="syslog-udp", input_name="bench",
                                 peer_ip=f"192.0.2.{(i // batch_size) % 250 + 1}") for l in chunk]
        t = time.perf_counter()
        stored += len(ingestor.ingest(records))
        latencies.append((time.perf_counter() - t) * 1000)
    wall = time.perf_counter() - t_start
    latencies.sort()
    return {"events": stored, "seconds": round(wall, 3), "events_per_second": round(stored / wall),
            "per_day_millions": round(stored / wall * 86400 / 1e6, 1),
            "batch_ms_p50": round(statistics.median(latencies), 2),
            "batch_ms_p99": round(latencies[int(len(latencies) * 0.99) - 1], 2),
            "parse_only_us_per_line": round(parse_only * 1e6, 1),
            "parse_share_pct": round(100 * parse_only * stored / wall, 1)}


def run_read(sample_ip: str):
    """Time what a person waits for: search, the dashboard, an export, and chain verification."""
    from backend.api.analytics import get_overview_kpis
    from backend.api.events import list_events
    from backend.api.export import export_ocsf_json
    from backend.services.integrity.ledger import IntegrityLedger

    def timed(label, fn):
        t = time.perf_counter()
        out = fn()
        return label, round((time.perf_counter() - t) * 1000, 1), out

    results = {}
    for label, ms, _ in [
        timed("events_page_ms", lambda: list_events(None, None, None, None, None, 50, 0, False)),
        timed("events_search_ms", lambda: list_events("denied", None, None, None, None, 50, 0, False)),
        timed("events_by_ip_ms", lambda: list_events(None, None, None, None, sample_ip, 50, 0, False)),
        timed("dashboard_ms", get_overview_kpis),
        timed("export_ocsf_ms", lambda: export_ocsf_json(1000)),
        timed("verify_chain_ms", IntegrityLedger.verify_chain),
    ]:
        results[label] = ms
    return results


def main():
    ap = argparse.ArgumentParser(description="TRACELOG throughput benchmark")
    ap.add_argument("-n", "--events", type=int, default=20000)
    ap.add_argument("-b", "--batch", type=int, default=500)
    ap.add_argument("-w", "--workers", type=int, default=1,
                    help="ingest shards to run at once, each with its own database and chain")
    ap.add_argument("--db", default=None, help="database file to use (default: a temporary one)")
    ap.add_argument("--read", action="store_true", help="also time search, dashboard, export and verification")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.workers > 1:
        sharded = run_sharded(args.workers, args.events, args.batch)
        if args.json:
            print(json.dumps(sharded, indent=2))
            return
        print(f"\n{sharded['workers']} shards, {args.events:,} events each, batches of {args.batch}")
        for r in sharded["per_shard"]:
            print(f"   shard {r['shard']}   {r['events']:,} events in {r['seconds']}s "
                  f"({round(r['events'] / r['seconds']):,} events/s)")
        print(f"\naggregate {sharded['events']:,} events in {sharded['ingest_seconds']}s "
              f"(wall clock including start-up: {sharded['wall_seconds']}s)")
        print(f"          {sharded['events_per_second']:,} events/s  ->  "
              f"{sharded['per_day_millions']}M/day on this machine")
        print("          each shard keeps its own hash chain, so nothing is shared between them")
        return

    tmp = tempfile.TemporaryDirectory()
    setup_database(Path(args.db) if args.db else Path(tmp.name) / "bench.db")
    lines = build_corpus(args.events)
    result = {"events_requested": args.events, "batch_size": args.batch, "ingest": run_ingest(lines, args.batch)}
    if args.read:
        result["read"] = run_read("10.0.0.5")

    if args.json:
        print(json.dumps(result, indent=2))
        return
    i = result["ingest"]
    print(f"\ningest   {i['events']:,} events in {i['seconds']}s")
    print(f"         {i['events_per_second']:,} events/s  ->  {i['per_day_millions']}M/day on this machine")
    print(f"         batch latency p50 {i['batch_ms_p50']} ms, p99 {i['batch_ms_p99']} ms "
          f"(batch of {args.batch})")
    print(f"         parsing alone {i['parse_only_us_per_line']} us/line, about {i['parse_share_pct']}% of the time")
    if args.read:
        print("\nread")
        for k, v in result["read"].items():
            print(f"         {k:<18} {v} ms")


if __name__ == "__main__":
    main()
