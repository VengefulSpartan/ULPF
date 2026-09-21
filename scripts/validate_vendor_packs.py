"""
Measure vendor-pack coverage on a corpus of real device logs.

Usage:
    python scripts/validate_vendor_packs.py <dir> [<dir> ...]

Each directory (or file) is scanned for *.log / *.txt / *.json files; every
non-empty line is parsed and normalised exactly as the ingestion pipeline
does. The report shows, per file: lines, which parser claimed them, the OCSF
classes produced, and how many events have both endpoints. No data leaves the
machine and nothing is written to the database.
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.normalization.ocsf_normalizer import OCSFNormalizer  # noqa: E402
from backend.services.parsing.dispatch import parse_log  # noqa: E402


def iter_files(paths):
    for p in map(Path, paths):
        if p.is_file():
            yield p
        else:
            for ext in ("*.log", "*.txt", "*.json"):
                yield from sorted(p.rglob(ext))


def main(paths):
    grand = Counter()
    for path in iter_files(paths):
        lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip()]
        if not lines:
            continue
        parsers, classes, endpoints = Counter(), Counter(), 0
        for line in lines:
            fmt, parsed = parse_log(line)
            ev = OCSFNormalizer.normalize(parsed, line, "r", "h")
            parsers[fmt] += 1
            classes[f"{ev.class_uid} {ev.class_name}"] += 1
            if ev.src_endpoint and ev.src_endpoint.ip and ev.dst_endpoint and ev.dst_endpoint.ip:
                endpoints += 1
        grand["lines"] += len(lines)
        grand["with_endpoints"] += endpoints
        print(f"\n{path} ({len(lines)} lines)")
        print("  parsers :", dict(parsers.most_common()))
        print("  classes :", dict(classes.most_common()))
        print(f"  src+dst : {endpoints}/{len(lines)}")
    print(f"\nTOTAL lines={grand['lines']} with src+dst={grand['with_endpoints']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
