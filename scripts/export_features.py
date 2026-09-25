#!/usr/bin/env python3
"""
Export per-entity window features for analytics or model training (docs/ML_DATA.md).

    python scripts/export_features.py                          # last 24 h from the TRACELOG database
    python scripts/export_features.py --hours 168 -o week.csv
    python scripts/export_features.py --parquet data/lake      # from the Parquet output's files instead
    python scripts/export_features.py --entity user --window 15 -o users.parquet

One row per (entity, window) in which the entity appears. Each row is computed from its own window
and earlier ones only, so the file can be split by time for training and testing without the test
rows leaking into training.
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, help="a TRACELOG database file (default: the configured one)")
    ap.add_argument("--parquet", type=Path, help="read the Parquet output's directory instead of the database")
    ap.add_argument("--hours", type=float, default=24, help="how far back to read from the database (default 24)")
    ap.add_argument("--entity", default="src_ip,user,device", help="src_ip, user, device, or a comma list")
    ap.add_argument("--window", type=int, default=5, help="window length in minutes (default 5)")
    ap.add_argument("-o", "--output", type=Path, default=Path("features.csv"), help=".csv or .parquet")
    args = ap.parse_args(argv)

    from backend.services.ml import features as feat
    if args.parquet:
        events = feat.events_from_parquet(args.parquet)
    else:
        database = None
        if args.db:
            from scripts.benchmark import setup_database
            database = setup_database(args.db)
        until = int(datetime.now(timezone.utc).timestamp() * 1000)
        events = feat.events_from_db(database, since_ms=until - int(args.hours * 3600 * 1000), until_ms=until)
    kinds = [k.strip() for k in args.entity.split(",") if k.strip()]
    unknown = [k for k in kinds if k not in feat.ENTITY_TYPES]
    if unknown:
        ap.error(f"unknown entity type(s): {', '.join(unknown)}")
    table = feat.all_features(events, args.window, kinds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.suffix == ".parquet":
        table.to_parquet(args.output, index=False)
    else:
        table.to_csv(args.output, index=False)
    print(f"{len(events)} events -> {len(table)} rows ({', '.join(f'{k}: {(table.entity_type == k).sum()}' for k in kinds)})"
          f" -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
