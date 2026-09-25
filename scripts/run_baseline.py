#!/usr/bin/env python3
"""
Run the baseline detector once (docs/ML_DATA.md): score the complete 5-minute windows of the last
hour (or --hours) against the previous 24 h, and write each flag as an OCSF Detection Finding
through the same writer as every log line.

    python scripts/run_baseline.py                     # last hour, write findings
    python scripts/run_baseline.py --hours 24 --dry-run
    python scripts/run_baseline.py --db other.db --until 2026-09-21T23:00:00Z

Running it again over the same period writes nothing new: each flag's id comes from its entity and
window, and a flag already stored is skipped. To run it continuously inside the API server, set
BASELINE_EVERY_MINUTES=5.
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, help="a TRACELOG database file (default: the configured one)")
    ap.add_argument("--hours", type=float, default=1, help="hours of windows to score (default 1)")
    ap.add_argument("--lookback", type=float, default=24, help="hours of history before them (default 24)")
    ap.add_argument("--until", help="ISO 8601 end of the scored period (default now)")
    ap.add_argument("--dry-run", action="store_true", help="print the flags, write nothing")
    args = ap.parse_args(argv)

    database = None
    if args.db:
        from scripts.benchmark import setup_database
        database = setup_database(args.db)
    from backend.services.ml import baseline
    until_ms = None
    if args.until:
        until_ms = int(datetime.fromisoformat(args.until.replace("Z", "+00:00")).timestamp() * 1000)
    result = baseline.run(database, until_ms=until_ms, score_hours=args.hours, lookback_hours=args.lookback,
                          write=not args.dry_run)
    print(f"scored {result['scored_from']} to {result['scored_until']}: {result['events_read']} events, "
          f"{result['windows_scored']} entity-windows scored, {result['windows_without_history']} without "
          f"enough history, {result['flags']} flagged, {result['findings_written']} findings written")
    for f in result["findings"]:
        print(f"  {f['window_start']}  {f['title']}\n      {f['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
